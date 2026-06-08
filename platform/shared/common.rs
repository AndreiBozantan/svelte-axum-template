use axum::Json;
use axum::response::IntoResponse;
use axum::response::Response;
use reqwest::StatusCode;
use serde::Deserialize;
use serde::Serialize;
use sqlx::error::DatabaseError;
use thiserror::Error;

use crate::config;
use crate::jwt::JwtContext;
use crate::jwt::JwtError;

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

impl From<DataValidationError> for ApiError {
    fn from(error: DataValidationError) -> Self {
        match error {
            DataValidationError::InvalidEmail => Self::invalid_credentials(),
        }
    }
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

impl From<RepoError> for ApiError {
    fn from(error: RepoError) -> Self {
        // TODO: use structured logging here
        tracing::error!("database error: {error}");

        #[allow(clippy::match_same_arms)]
        match error {
            RepoError::RowNotFound => Self::not_found(),
            RepoError::UniqueViolation(_) => Self::db_key_violation("unique_violation"),
            RepoError::ForeignKeyViolation(_) => Self::db_key_violation("foreign_key_violation"),
            RepoError::CheckViolation(_) => Self::db_key_violation("check_violation"),
            RepoError::Database(_) => Self::internal(),
            RepoError::RowConversionFailed(_) => Self::internal(),
        }
    }
}

fn is_check_violation(db_err: &dyn DatabaseError) -> bool {
    db_err
        .code()
        .is_some_and(|code| code.as_ref() == "2067" || code.as_ref() == "275")
}

#[derive(Debug, Clone, Error)]
#[error("{message}")]
pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
    details: Option<serde_json::Value>,
}

impl From<JwtError> for ApiError {
    fn from(error: JwtError) -> Self {
        tracing::error!("JWT error: {error}");
        match error {
            JwtError::TokenExpired => Self::expired_token(),
            JwtError::InvalidToken => Self::invalid_token(),
            _ => Self::internal(),
        }
    }
}

#[derive(Serialize)]
struct ApiErrorBody {
    code: &'static str,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<serde_json::Value>,
}

impl ApiError {
    #[must_use]
    pub fn new(
        status: StatusCode,
        code: &'static str,
        message: impl Into<String>,
        details: Option<serde_json::Value>,
    ) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            details,
        }
    }

    #[must_use]
    pub const fn status(&self) -> StatusCode {
        self.status
    }

    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    #[must_use]
    pub fn message(&self) -> String {
        self.message.clone()
    }

    #[must_use]
    pub fn details(&self) -> Option<serde_json::Value> {
        self.details.clone()
    }

    #[must_use]
    pub fn internal() -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", "An unexpected error occured.", None)
    }

    #[must_use]
    pub fn invalid_credentials() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "invalid_credentials", "Email or password is incorrect", None)
    }

    #[must_use]
    pub fn not_authenticated() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "not_authenticated", "Authentication is required.", None)
    }

    #[must_use]
    pub fn sso_failed() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "sso_failed", "Single sign-on authentication failed.", None)
    }

    #[must_use]
    pub fn expired_token() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "expired_token", "Authentication token has expired.", None)
    }

    #[must_use]
    pub fn invalid_token() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "invalid_token", "Authentication token is invalid.", None)
    }

    #[must_use]
    pub fn forbidden() -> Self {
        Self::new(StatusCode::FORBIDDEN, "forbidden", "The requested operation is not allowed.", None)
    }

    #[must_use]
    pub fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", "The requested resource is not found.", None)
    }

    #[must_use]
    pub fn validation_failed(details: serde_json::Value) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "validation_failed", "Request validation failed.", Some(details))
    }

    #[must_use]
    pub fn user_already_exists() -> Self {
        Self::conflict("user_already_exists", "A user with the given email already exists.")
    }

    #[must_use]
    pub fn db_key_violation(code: &'static str) -> Self {
        Self::conflict(code, "A data validation error occurred.")
    }

    #[must_use]
    pub fn conflict(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, code, message, None)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status();
        let body = ApiErrorBody {
            code: self.code(),
            message: self.message(),
            details: self.details(),
        };
        (status, Json(body)).into_response()
    }
}

pub struct Context {
    pub db: SqlContext,
    pub jwt: JwtContext,
    pub settings: config::AppSettings,
    pub http_client: reqwest::Client,
}

#[derive(Deserialize)]
pub struct Pagination {
    #[serde(default = "default_pagination_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

const fn default_pagination_limit() -> i64 {
    20
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

impl Pagination {
    #[must_use]
    pub fn sanitize(&self) -> (i64, i64) {
        let limit = self.limit.clamp(1, 200);
        let offset = self.offset.max(0);
        (limit, offset)
    }
}
