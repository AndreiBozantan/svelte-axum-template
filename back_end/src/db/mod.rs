pub mod schema;
pub mod migrations;

use std::path::Path;
use std::str::FromStr;
use thiserror::Error;

use sqlx::{SqlitePool};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

pub use crate::appconfig::DatabaseConfig;
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

    // Determine the migrations path
    let migrations_path = Path::new("./back_end/migrations");

    // Run migrations using our migrations module
    migrations::run(&pool, migrations_path).await?;

    tracing::info!("Database initialized successfully");
    Ok(pool)
}