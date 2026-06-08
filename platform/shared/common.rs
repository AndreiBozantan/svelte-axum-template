use sqlx::error::DatabaseError;
use thiserror::Error;

use crate::config;
use crate::jwt::JwtContext;

pub type SqlContext = sqlx::SqlitePool;
pub type SqlError = sqlx::Error;
pub type ArcContext = std::sync::Arc<Context>;
pub type AppContext = axum::extract::State<ArcContext>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UserId(pub i64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TenantId(pub i64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Email(String);

impl Email {
    pub fn parse(raw: &str) -> Result<Self, DataValidationError> {
        let normalized = raw.trim().to_ascii_lowercase();
        if normalized.is_empty() || !normalized.contains('@') {
            return Err(DataValidationError::InvalidEmail);
        }
        Ok(Self(normalized))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Error)]
pub enum DataValidationError {
    #[error("invalid email address")]
    InvalidEmail,
}

#[derive(Debug, Error)]
pub enum RepoError {
    #[error("entity not found")]
    RowNotFound,

    #[error("unique constraint violation: {0}")]
    UniqueViolation(String),

    #[error("foreign key violation: {0}")]
    ForeignKeyViolation(String),

    #[error("check constraint violation: {0}")]
    CheckViolation(String),

    #[error("database error: {0}")]
    Database(SqlError),

    #[error("row conversion error: {0}")]
    RowConversionFailed(String),
}

impl From<DataValidationError> for RepoError {
    fn from(error: DataValidationError) -> Self {
        match error {
            DataValidationError::InvalidEmail => Self::RowConversionFailed("invalid email address".to_string()),
        }
    }
}

impl From<SqlError> for RepoError {
    fn from(error: SqlError) -> Self {
        fn is_check_violation(db_err: &dyn DatabaseError) -> bool {
            db_err
                .code()
                .is_some_and(|code| code.as_ref() == "2067" || code.as_ref() == "275")
        }

        if let SqlError::Database(db_err) = &error {
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
            SqlError::RowNotFound => Self::RowNotFound,
            other => Self::Database(other),
        }
    }
}

pub struct Context {
    pub db: SqlContext,
    pub jwt: JwtContext,
    pub settings: config::AppSettings,
    pub http_client: reqwest::Client,
}


impl Context {
    #[must_use]
    pub const fn new(
        db: SqlContext,
        jwt: JwtContext,
        settings: config::AppSettings,
        http_client: reqwest::Client,
    ) -> Self {
        Self {
            db,
            jwt,
            settings,
            http_client,
        }
    }

    #[must_use]
    pub fn env(&self) -> &str {
        &self.settings.server.env
    }

    #[must_use]
    pub fn is_prod_env(&self) -> bool {
        self.settings.server.env == crate::constants::env::PRODUCTION
    }

    #[must_use]
    pub fn is_dev_env(&self) -> bool {
        self.settings.server.env == crate::constants::env::DEVELOPMENT
    }

    #[must_use]
    pub fn is_test_env(&self) -> bool {
        self.settings.server.env == crate::constants::env::TEST
    }
}

