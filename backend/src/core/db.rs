use std::str::FromStr;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use thiserror::Error;

use crate::core::config::DatabaseConfig;

pub type DbPoolType = sqlx::SqlitePool;

#[derive(Debug, Error)]
pub enum DbError {
    #[error("Database connection error: {0}")]
    ConnectionFailed(sqlx::Error),

    #[error("Database operation failed: {0}")]
    OperationFailed(#[from] sqlx::Error),

    #[error("User not found")]
    UserNotFound,

    #[error("Token not found")]
    TokenNotFound,

    #[error("Tenant not found")]
    TenantNotFound,
}

pub async fn create_db_pool(db_config: &DatabaseConfig) -> Result<DbPoolType, DbError> {
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

    tracing::info!("Database initialized successfully");
    Ok(pool)
}
