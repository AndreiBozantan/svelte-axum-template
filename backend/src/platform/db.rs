use std::str::FromStr;

use sqlx::sqlite::SqliteConnectOptions;
use sqlx::sqlite::SqlitePoolOptions;

use crate::platform::config;
use crate::platform::db;

pub type SqlContext = sqlx::SqlitePool;
pub type SqlError = sqlx::Error;

pub async fn create_context(db_config: &config::DatabaseSettings) -> Result<db::SqlContext, db::SqlError> {
    let options = SqliteConnectOptions::from_str(&db_config.url)?
        .create_if_missing(true)
        .foreign_keys(true)
        // Increase SQLite busy timeout to handle concurrent connections better
        .busy_timeout(std::time::Duration::from_secs(30));
    let pool = SqlitePoolOptions::new()
        .max_connections(db_config.max_connections)
        .connect_with(options)
        .await?;
    // enable WAL mode for better concurrency
    sqlx::query("PRAGMA journal_mode = WAL").execute(&pool).await?;
    if db_config.store_temp_tables_in_memory {
        // store temporary tables in memory for better performance
        sqlx::query("PRAGMA temp_store = MEMORY").execute(&pool).await?;
    }
    Ok(pool)
}
