use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use anyhow::Result;
use chrono::{Utc, Local, TimeZone};
use sqlx::{Pool, Sqlite};

/// Runs all migrations from the filesystem migration path
pub async fn run_migrations(pool: &Pool<Sqlite>, migrations_path: &Path) -> Result<()> {
    if !migrations_path.exists() {
        tracing::warn!("Migrations directory not found at {:?}, falling back to embedded migrations", migrations_path);
        // Run migrations from embedded
        sqlx::migrate!()
            .run(pool)
            .await
            .map_err(|e| {
                tracing::error!("Failed to run database migrations: {:?}", e);
                anyhow::anyhow!("Failed to run embedded migrations: {}", e)
            })?;
    } else {
        // Run migrations from the filesystem
        sqlx::migrate::Migrator::new(migrations_path)
            .await
            .map_err(|e| {
                tracing::error!("Failed to create migrator: {:?}", e);
                anyhow::anyhow!("Failed to create migrator: {}", e)
            })?
            .run(pool)
            .await
            .map_err(|e| {
                tracing::error!("Failed to run database migrations: {:?}", e);
                anyhow::anyhow!("Failed to run migrations: {}", e)
            })?;
    }

    tracing::info!("Database migrations completed successfully");
    Ok(())
}

/// Create a new migration file with the current timestamp
pub fn create_migration(name: &str) -> Result<String> {
    let migrations_dir = Path::new("./back_end/migrations");

    // Create migrations directory if it doesn't exist
    if !migrations_dir.exists() {
        fs::create_dir_all(migrations_dir)?;
    }

    // Generate a timestamp in the format YYYYMMDDHHMMSS
    let seconds = SystemTime::now().duration_since(UNIX_EPOCH)
        .map_err(|e| anyhow::anyhow!("Error getting system time: {}", e))?
        .as_secs();

    // Properly convert seconds to DateTime<Utc>
    let now = Utc.timestamp_opt(seconds as i64, 0).single()
        .ok_or_else(|| anyhow::anyhow!("Failed to create timestamp"))?;

    let timestamp = now.format("%Y%m%d%H%M%S").to_string();
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
pub fn list_migrations() -> Result<Vec<String>> {
    let migrations_dir = Path::new("./back_end/migrations");

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

/// Check if migrations need to be applied
pub async fn check_pending_migrations(pool: &Pool<Sqlite>) -> Result<bool> {
    // Get the list of applied migrations from the database
    let applied_migrations = sqlx::query!("SELECT version FROM _sqlx_migrations ORDER BY version")
        .fetch_all(pool)
        .await
        .map_err(|e| {
            if e.to_string().contains("no such table") {
                // The _sqlx_migrations table doesn't exist yet, which means no migrations have been applied
                return anyhow::anyhow!("No migrations applied yet");
            }
            anyhow::anyhow!("Failed to fetch applied migrations: {}", e)
        })?;

    // Get the list of available migrations
    let available_migrations = list_migrations()?;

    // Check if there are any migrations that haven't been applied
    let applied_names: Vec<String> = applied_migrations.into_iter()
        .map(|row| row.version.unwrap_or_default().to_string())
        .collect();

    Ok(available_migrations.len() > applied_names.len())
}