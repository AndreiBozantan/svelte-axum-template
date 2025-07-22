use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::time::{UNIX_EPOCH, SystemTime, SystemTimeError as StdSystemTimeError};

use chrono::{Utc, Local, TimeZone};
use sqlx::{Error as SqlxError, migrate::MigrateError as SqlxMigrateError};
use thiserror::Error;

use crate::app;
use crate::core::DbContext;

#[derive(Debug, Error)]
pub enum MigrationError {
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

/// Runs all migrations from the filesystem migration path
pub async fn run_migrations(db: &DbContext) -> Result<(), MigrationError> {
    let migrations_path = migrations_path();
    if !migrations_path.exists() {
        tracing::warn!("Migrations directory not found at {:?}, falling back to embedded migrations", migrations_path);
        // Run migrations from embedded
        sqlx::migrate!()
            .run(db)
            .await
            .map_err(|e| MigrationError::EmbeddedMigrationFailed { source: e })?;
    } else {
        // Run migrations from the filesystem
        sqlx::migrate::Migrator::new(migrations_path)
            .await
            .map_err(|e| MigrationError::MigratorCreationFailed { source: e })?
            .run(db)
            .await
            .map_err(|e| MigrationError::MigrationRunFailed { source: e })?;
    }
    tracing::info!("Database migrations completed successfully");
    Ok(())
}

/// Check if migrations need to be applied
pub async fn check_pending_migrations(db: &DbContext) -> Result<bool, MigrationError> {
    // Get the list of applied migrations from the database
    let applied_migrations = sqlx::query!("SELECT version FROM _sqlx_migrations ORDER BY version")
        .fetch_all(db)
        .await
        .map_err(|err| {
            match &err {
                sqlx::Error::Database(db_err) if db_err.message().contains("no such table") => MigrationError::NoMigrationsApplied,
                _ => MigrationError::FetchAppliedMigrationsFailed { source: err },
            }
        })?;

    // Get the list of available migrations
    let available_migrations = app::list_migrations()?;

    // Check if there are any migrations that haven't been applied
    let applied_names: Vec<String> = applied_migrations.into_iter()
        .map(|row| row.version.unwrap_or_default().to_string())
        .collect();

    Ok(available_migrations.len() > applied_names.len())
}

/// Create a new migration file with the current timestamp
pub fn create_migration(name: &str) -> Result<String, MigrationError> {
    let migrations_dir = Path::new(migrations_path());

    // Create migrations directory if it doesn't exist
    if !migrations_dir.exists() {
        fs::create_dir_all(migrations_dir)?;
    }

    // Generate a timestamp in the format YYYYMMDD_HHMMSS
    let seconds = SystemTime::now().duration_since(UNIX_EPOCH)
        .map_err(|e| MigrationError::SystemTimeFailed { source: e })?
        .as_secs();

    // Properly convert seconds to DateTime<Utc>
    let now = Utc.timestamp_opt(seconds as i64, 0).single()
        .ok_or(MigrationError::TimestampConversionFailed)?;

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
pub fn list_migrations() -> Result<Vec<String>, MigrationError> {
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
