pub mod schema;
pub mod migrations;

use std::path::Path;
use std::sync::Arc;
use std::str::FromStr;

use anyhow::Result;
use sqlx::{Pool, Sqlite};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

pub use crate::appconfig::DatabaseConfig;

pub type DbPool = Pool<Sqlite>;
pub type DbPoolRef = Arc<DbPool>;

pub async fn init_pool(db_config: &DatabaseConfig) -> Result<DbPoolRef> {
    let options = SqliteConnectOptions::from_str(&db_config.url)?
            .create_if_missing(true)
            .foreign_keys(true)
            // Increase SQLite busy timeout to handle concurrent connections better
            .busy_timeout(std::time::Duration::from_secs(30));

    let pool = SqlitePoolOptions::new()
        .max_connections(db_config.max_connections)
        .connect_with(options)
        .await?;

    // Determine the migrations path
    let migrations_path = Path::new("./back_end/migrations");

    // Run migrations using our migrations module
    migrations::run(&pool, migrations_path).await?;

    tracing::info!("Database initialized successfully");
    Ok(Arc::new(pool))
}