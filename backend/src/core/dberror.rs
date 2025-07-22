use thiserror::Error;

#[derive(Debug, Error)]
pub enum DbError {
    #[error("Database connection error: {0}")]
    ConnectionFailed(sqlx::Error),

    #[error("Database operation failed: {0}")]
    OperationFailed(sqlx::Error),

    #[error("Row not found")]
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