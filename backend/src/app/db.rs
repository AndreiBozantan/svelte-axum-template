use std::str::FromStr;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH, SystemTimeError as StdSystemTimeError};

use chrono::{Utc, Local, TimeZone};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Error as SqlxError, migrate::MigrateError as SqlxMigrateError};
use thiserror::Error;

use crate::app;
use crate::core;
use crate::store;

pub type DbPoolType = sqlx::SqlitePool;

pub struct Database {
    pub refresh_tokens: store::RefreshTokens,
    pub tenants: store::Tenants,
    pub users: store::Users,

    pool: DbPoolType,
}

#[derive(Debug, Error)]
pub enum DbError {
    #[error("Database connection error: {0}")]
    ConnectionFailed(sqlx::Error),

    #[error("Database operation failed: {0}")]
    OperationFailed(#[from] sqlx::Error),

    #[error("Database migration error: {0}")]
    MigrationFailed(#[from] DbMigrationError),

    #[error("User not found")]
    UserNotFound,

    #[error("Token not found")]
    TokenNotFound,

    #[error("Tenant not found")]
    TenantNotFound,
}

#[derive(Debug, Error)]
pub enum DbMigrationError {
    #[error("Failed to run embedded migrations")]
    EmbeddedMigrationFailed { #[source] source: SqlxMigrateError },

    #[error("Failed to create migrator")]
    MigratorCreationFailed { #[source] source: SqlxMigrateError },

    #[error("Failed to run migrations")]
    MigrationRunFailed { #[source] source: SqlxMigrateError },

    #[error("Error getting system time")]
    SystemTimeFailed { #[source] source: StdSystemTimeError },

    #[error("Failed to create timestamp")]
    TimestampConversionFailed,

    #[error("Failed to fetch applied migrations")]
    FetchAppliedMigrationsFailed { #[source] source: SqlxError },

    #[error("No migrations applied yet")]
    NoMigrationsApplied,

    #[error("File system error")]
    FileSystemOperationFailed(#[from] std::io::Error),
}

fn migrations_path() -> &'static Path {
    match Path::new("backend").exists() {
        true => Path::new("backend/migrations"),
        false => Path::new("migrations")
    }
}


impl Database {
    pub async fn new(db_config: &core::DatabaseConfig) -> Result<Self, DbError> {
        let options = SqliteConnectOptions::from_str(&db_config.url)
            .map_err(DbError::ConnectionFailed)?
            .create_if_missing(true)
            .foreign_keys(true)
            // Increase SQLite busy timeout to handle concurrent connections better
            .busy_timeout(std::time::Duration::from_secs(30));

        let pool = SqlitePoolOptions::new()
            .max_connections(db_config.max_connections)
            .connect_with(options)
            .await
            .map_err(|e| DbError::ConnectionFailed(e))?;

        let database = Self {
            users: store::Users::new(pool.clone()),
            tenants: store::Tenants::new(pool.clone()),
            refresh_tokens: store::RefreshTokens::new(pool.clone()),
            pool,
        };

        // Run migrations if run_db_migrations_on_startup is enabled
        if !db_config.run_db_migrations_on_startup {
            tracing::info!("Database migrations skipped (run_db_migrations_on_startup  = false)");
        } else {
            // if there is a backend directory in the current working directory, use that as the migrations path
            // Run migrations using our migrations module
            database.run_migrations().await?;
            tracing::info!("Database migrations completed successfully");
        }

        tracing::info!("Database initialized successfully");
        Ok(database)
    }

    /// Runs all migrations from the filesystem migration path
    pub async fn run_migrations(&self) -> Result<(), DbMigrationError> {
        let migrations_path = migrations_path();
        if !migrations_path.exists() {
            tracing::warn!("Migrations directory not found at {:?}, falling back to embedded migrations", migrations_path);
            // Run migrations from embedded
            sqlx::migrate!()
                .run(&self.pool)
                .await
                .map_err(|e| DbMigrationError::EmbeddedMigrationFailed { source: e })?;
        } else {
            // Run migrations from the filesystem
            sqlx::migrate::Migrator::new(migrations_path)
                .await
                .map_err(|e| DbMigrationError::MigratorCreationFailed { source: e })?
                .run(&self.pool)
                .await
                .map_err(|e| DbMigrationError::MigrationRunFailed { source: e })?;
        }
        tracing::info!("Database migrations completed successfully");
        Ok(())
    }

    /// Check if migrations need to be applied
    pub async fn check_pending_migrations(&self) -> Result<bool, DbMigrationError> {
        // Get the list of applied migrations from the database
        let applied_migrations = sqlx::query!("SELECT version FROM _sqlx_migrations ORDER BY version")
            .fetch_all(&self.pool)
            .await
            .map_err(|err| {
                match &err {
                    sqlx::Error::Database(db_err) if db_err.message().contains("no such table") => DbMigrationError::NoMigrationsApplied,
                    _ => DbMigrationError::FetchAppliedMigrationsFailed { source: err },
                }
            })?;

        // Get the list of available migrations
        let available_migrations = self.list_migrations()?;

        // Check if there are any migrations that haven't been applied
        let applied_names: Vec<String> = applied_migrations.into_iter()
            .map(|row| row.version.unwrap_or_default().to_string())
            .collect();

        Ok(available_migrations.len() > applied_names.len())
    }

    /// Create a new migration file with the current timestamp
    pub fn create_migration(&self, name: &str) -> Result<String, DbMigrationError> {
        let migrations_dir = Path::new(migrations_path());

        // Create migrations directory if it doesn't exist
        if !migrations_dir.exists() {
            fs::create_dir_all(migrations_dir)?;
        }

        // Generate a timestamp in the format YYYYMMDD_HHMMSS
        let seconds = SystemTime::now().duration_since(UNIX_EPOCH)
            .map_err(|e| DbMigrationError::SystemTimeFailed { source: e })?
            .as_secs();

        // Properly convert seconds to DateTime<Utc>
        let now = Utc.timestamp_opt(seconds as i64, 0).single()
            .ok_or(DbMigrationError::TimestampConversionFailed)?;

        let timestamp = now.format("%Y%m%d_%H%M%S").to_string();
        let filename = format!("{}_{}.sql", timestamp, name.replace(" ", "_").to_lowercase());
        let filepath = migrations_dir.join(&filename);

        // Create the migration file with template content
        let mut file = File::create(&filepath)?;
        writeln!(file, "-- Migration: {}", name)?;
        writeln!(file, "-- Created at: {}", Local::now().format("%Y-%m-%d %H:%M:%S"))?;
        writeln!(file, "--")?;
        writeln!(file, "-- Add migration script here")?;

        tracing::info!("Created new migration file: {}", filepath.display());
        Ok(filename)
    }

    /// List all available migrations
    pub fn list_migrations(&self) -> Result<Vec<String>, DbMigrationError> {
        let migrations_dir = Path::new(migrations_path());

        if !migrations_dir.exists() {
            return Ok(Vec::new());
        }

        let mut migrations = Vec::new();
        for entry in fs::read_dir(migrations_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() && path.extension().map_or(false, |ext| ext == "sql") {
                if let Some(filename) = path.file_name() {
                    if let Some(filename_str) = filename.to_str() {
                        migrations.push(filename_str.to_string());
                    }
                }
            }
        }

        migrations.sort();
        Ok(migrations)
    }
}
