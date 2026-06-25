use sqlx::error::DatabaseError;
use thiserror::Error;

use crate::platform::config;

pub type Context = sqlx::SqlitePool;

pub async fn create_context(db_config: &config::DatabaseSettings) -> Result<Context, sqlx::Error> {
    use sqlx::Executor;
    use std::str::FromStr;

    let options = sqlx::sqlite::SqliteConnectOptions::from_str(&db_config.url)?
        .create_if_missing(true)
        .foreign_keys(true)
        .busy_timeout(std::time::Duration::from_secs(db_config.write_busy_timeout_seconds))
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);

    let mut pool_options = sqlx::sqlite::SqlitePoolOptions::new().max_connections(db_config.max_connections);

    // attach a hook that runs automatically every time a new connection is established
    if db_config.store_temp_tables_in_memory {
        pool_options = pool_options.after_connect(|conn, _meta| {
            Box::pin(async move {
                conn.execute("PRAGMA temp_store = MEMORY").await?;
                Ok(())
            })
        });
    }

    let pool = pool_options.connect_with(options).await?;

    Ok(pool)
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("entity not found")]
    RowNotFound,

    #[error("unique constraint violation: {0}")]
    UniqueConstraintViolation(String),

    #[error("foreign key violation: {0}")]
    ForeignKeyViolation(String),

    #[error("check constraint violation: {0}")]
    CheckConstraintViolation(String),

    #[error("database error: {0}")]
    DatabaseOperationFailed(sqlx::Error),

    #[error("row conversion error: {0}")]
    RowConversionFailed(String),
}

impl From<sqlx::Error> for Error {
    fn from(error: sqlx::Error) -> Self {
        fn is_check_violation(db_err: &dyn DatabaseError) -> bool {
            db_err.code().is_some_and(|code| code.as_ref() == "275")
        }

        if let sqlx::Error::Database(db_err) = &error {
            let message = db_err.message().to_string();
            if db_err.is_unique_violation() {
                return Self::UniqueConstraintViolation(message);
            }
            if db_err.is_foreign_key_violation() {
                return Self::ForeignKeyViolation(message);
            }
            if is_check_violation(db_err.as_ref()) {
                return Self::CheckConstraintViolation(message);
            }
        }
        match error {
            sqlx::Error::RowNotFound => Self::RowNotFound,
            other => Self::DatabaseOperationFailed(other),
        }
    }
}
