use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::Path;

use chrono;
use sqlx::Error as SqlxError;
use sqlx::migrate::MigrateError as SqlxMigrateError;
use thiserror::Error;

use crate::app;
use crate::core::DbContext;

#[rustfmt::skip]
#[derive(Debug, Error)]
pub enum MigrationError {
    #[error("Failed to run embedded migrations")]
    EmbeddedMigrationFailed { source: SqlxMigrateError },

    #[error("Failed to create migrator")]
    MigratorCreationFailed { source: SqlxMigrateError },

    #[error("Failed to run migrations")]
    MigrationRunFailed { source: SqlxMigrateError },

    #[error("Failed to create timestamp")]
    TimestampConversionFailed,

    #[error("No migrations applied yet")]
    NoMigrationsApplied,

    #[error("Failed to fetch applied migrations")]
    FetchAppliedMigrationsFailed { #[from] source: SqlxError },

    #[error("File system error")]
    FileSystemOperationFailed { #[from] source: std::io::Error },
}

/// List all available migrations
#[must_use]
pub fn list_migrations() -> Vec<String> {
    sqlx::migrate!("../migrations")
        .iter()
        .map(|m| m.description.to_string())
        .collect::<Vec<_>>()
}

/// Runs the embedded migrations
pub async fn run_migrations(db: &DbContext) -> Result<(), MigrationError> {
    sqlx::migrate!("../migrations")
        .run(db)
        .await
        .map_err(|e| MigrationError::EmbeddedMigrationFailed { source: e })?;
    tracing::info!("Database migrations completed successfully.");
    Ok(())
}

/// Check if migrations need to be applied
pub async fn check_pending_migrations(db: &DbContext) -> Result<bool, MigrationError> {
    let available_migrations = app::list_migrations();
    let applied_migrations = sqlx::query!("SELECT version FROM _sqlx_migrations ORDER BY version")
        .fetch_all(db)
        .await
        .map_err(|err| match &err {
            sqlx::Error::Database(e) if e.message().contains("no such table") => MigrationError::NoMigrationsApplied,
            _ => MigrationError::FetchAppliedMigrationsFailed { source: err },
        })?;
    Ok(available_migrations.len() > applied_migrations.len())
}

/// Create a new migration file with a versioned name and template content.
pub fn create_migration(name: &str) -> Result<String, MigrationError> {
    // Create migrations directory if it doesn't exist
    let migrations_path = Path::new("migrations");
    if !migrations_path.exists() {
        std::fs::create_dir_all(migrations_path)?;
    }

    // Determine the max version using flat iterator combinators
    let max_version = fs::read_dir(migrations_path)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .filter_map(|path| path.file_name()?.to_str().map(String::from))
        .filter(|name| name.len() > 2)
        .filter_map(|name| name.get(0..2)?.parse::<u32>().ok())
        .max()
        .unwrap_or(0);

    // Increment and format the version string
    let next_version = max_version + 1;
    let version_string = format!("{next_version:02}");

    // Generate date and time for the file content
    let timestamp = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    
    // Construct filename and path
    let normalized_name = name.replace(' ', "_").to_lowercase();
    let filename = format!("{version_string}_{normalized_name}.sql");
    let filepath = migrations_path.join(&filename);

    // Create the migration file with template content
    let mut file = File::create(&filepath)?;
    writeln!(file, "-- Migration: {name}")?;
    writeln!(file, "-- Created at: {timestamp}")?;
    writeln!(file, "--")?;
    writeln!(file, "-- Add migration script here")?;

    tracing::info!("Created new migration file: {}.", filepath.display());
    Ok(filename)
}
