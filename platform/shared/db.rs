use sqlx::error::DatabaseError;
use thiserror::Error;
use crate::common::DataValidationError;

pub type Context = sqlx::SqlitePool;

#[derive(Debug, Error)]
pub enum Error {
    #[error("entity not found")]
    RowNotFound,

    #[error("unique constraint violation: {0}")]
    UniqueViolation(String),

    #[error("foreign key violation: {0}")]
    ForeignKeyViolation(String),

    #[error("check constraint violation: {0}")]
    CheckViolation(String),

    #[error("database error: {0}")]
    DatabaseOperationFailed(sqlx::Error),

    #[error("row conversion error: {0}")]
    RowConversionFailed(String),
}

impl From<DataValidationError> for Error {
    fn from(error: DataValidationError) -> Self {
        match error {
            DataValidationError::InvalidEmail => Self::RowConversionFailed("invalid email address".to_string()),
        }
    }
}

impl From<sqlx::Error> for Error {
    fn from(error: sqlx::Error) -> Self {
        fn is_check_violation(db_err: &dyn DatabaseError) -> bool {
            db_err
                .code()
                .is_some_and(|code| code.as_ref() == "2067" || code.as_ref() == "275")
        }

        if let sqlx::Error::Database(db_err) = &error {
            let message = db_err.message().to_string();
            if db_err.is_unique_violation() {
                return Self::UniqueViolation(message);
            }
            if db_err.is_foreign_key_violation() {
                return Self::ForeignKeyViolation(message);
            }
            if is_check_violation(db_err.as_ref()) {
                return Self::CheckViolation(message);
            }
        }
        match error {
            sqlx::Error::RowNotFound => Self::RowNotFound,
            other => Self::DatabaseOperationFailed(other),
        }
    }
}
