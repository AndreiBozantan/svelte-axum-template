use thiserror::Error;

// TODO: consider moving to the db module

#[derive(Debug, Error)]
pub enum DbError {
    #[error("Database connection error: {0}")]
    ConnectionFailed(sqlx::Error),

    #[error("Database operation failed: {0}")]
    OperationFailed(sqlx::Error),

    #[error("Row not found: {0}")]
    RowNotFound(sqlx::Error),
}

impl From<sqlx::Error> for DbError {
    fn from(error: sqlx::Error) -> Self {
        match error {
            sqlx::Error::RowNotFound => DbError::RowNotFound(error),
            _ => DbError::OperationFailed(error),
        }
    }
}