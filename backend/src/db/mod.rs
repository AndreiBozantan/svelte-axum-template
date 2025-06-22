mod store;
pub mod schema;
pub mod migrations;
pub use store::Store;
pub use store::StoreError;

use std::path::Path;
use std::str::FromStr;
use thiserror::Error;
use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

use crate::app::DatabaseConfig;

pub type DbPool = SqlitePool;

#[derive(Debug, Error)]
pub enum DbError {
    #[error("Failed to parse database URL")]
    ConnectionStringError(#[from] sqlx::Error),

    #[error("Failed to connect to database")]
    ConnectionError(#[source] sqlx::Error),

    #[error("Migration error: {0}")]
    MigrationError(#[from] migrations::MigrationError),
}

pub async fn init_pool(db_config: &DatabaseConfig) -> Result<DbPool, DbError> {
    let options = SqliteConnectOptions::from_str(&db_config.url)?
            .create_if_missing(true)
            .foreign_keys(true)
            // Increase SQLite busy timeout to handle concurrent connections better
            .busy_timeout(std::time::Duration::from_secs(30));

    let pool = SqlitePoolOptions::new()
        .max_connections(db_config.max_connections)
        .connect_with(options)
        .await
        .map_err(DbError::ConnectionError)?; // Updated to use the new variant

    // Run migrations if run_db_migrations_on_startup is enabled
    if !db_config.run_db_migrations_on_startup {
        tracing::info!("Database migrations skipped (run_db_migrations_on_startup  = false)");
    } else {
        // if there is a backend directory in the current working directory, use that as the migrations path
        let migrations_path = match Path::new("backend").exists() {
            true => Path::new("backend/migrations"),
            false => Path::new("migrations")
        };

        // Run migrations using our migrations module
        migrations::run(&pool, migrations_path).await?;
        tracing::info!("Database migrations completed successfully");
    }

    tracing::info!("Database initialized successfully");
    Ok(pool)
}