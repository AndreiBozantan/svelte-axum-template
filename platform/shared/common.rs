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
    NotFound,

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
            SqlError::RowNotFound => Self::NotFound,
            other => Self::Database(other),
        }
    }
}

fn is_check_violation(db_err: &dyn DatabaseError) -> bool {
    db_err
        .code()
        .is_some_and(|code| code.as_ref() == "2067" || code.as_ref() == "275")
}

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("An unexpected error occured.")]
    Internal,

    #[error("Email or password is incorrect")]
    InvalidCredentials,

    #[error("Authentication is required.")]
    NotAuthenticated,

    #[error("Single sign-on authentication failed.")]
    SsoFailed,

    #[error("Authentication token has expired.")]
    ExpiredToken,

    #[error("Authentication token is invalid.")]
    InvalidToken,

    #[error("The requested operation is not allowed.")]
    Forbidden,

    #[error("The requested resource is not found.")]
    NotFound,

    #[error("Request validation failed.")]
    ValidationFailed { details: serde_json::Value },

    #[error("{message}")]
    Conflict { code: &'static str, message: String },
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
    pub const fn internal() -> Self {
        Self::Internal
    }

    #[must_use]
    pub const fn invalid_credentials() -> Self {
        Self::InvalidCredentials
    }

    #[must_use]
    pub const fn not_authenticated() -> Self {
        Self::NotAuthenticated
    }

    #[must_use]
    pub const fn sso_failed() -> Self {
        Self::SsoFailed
    }

    #[must_use]
    pub const fn expired_token() -> Self {
        Self::ExpiredToken
    }

    #[must_use]
    pub const fn invalid_token() -> Self {
        Self::InvalidToken
    }

    #[must_use]
    pub const fn forbidden() -> Self {
        Self::Forbidden
    }

    #[must_use]
    pub const fn not_found() -> Self {
        Self::NotFound
    }

    #[must_use]
    pub const fn validation_failed(details: serde_json::Value) -> Self {
        Self::ValidationFailed { details }
    }

    #[must_use]
    pub fn user_already_exists() -> Self {
        Self::conflict("user_already_exists", "A user with the given email already exists.")
    }

    #[must_use]
    pub fn conflict(code: &'static str, message: impl Into<String>) -> Self {
        Self::Conflict {
            code,
            message: message.into(),
        }
    }

    #[must_use]
    pub const fn status(&self) -> StatusCode {
        match self {
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
            Self::InvalidCredentials
            | Self::NotAuthenticated
            | Self::SsoFailed
            | Self::ExpiredToken
            | Self::InvalidToken => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::ValidationFailed { .. } => StatusCode::BAD_REQUEST,
            Self::Conflict { .. } => StatusCode::CONFLICT,
        }
    }

    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Internal => "internal_error",
            Self::InvalidCredentials => "invalid_credentials",
            Self::NotAuthenticated => "not_authenticated",
            Self::SsoFailed => "sso_failed",
            Self::ExpiredToken => "expired_token",
            Self::InvalidToken => "invalid_token",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::ValidationFailed { .. } => "validation_failed",
            Self::Conflict { code, .. } => code,
        }
    }

    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::Internal => "An unexpected error occured.".to_string(),
            Self::InvalidCredentials => "Email or password is incorrect".to_string(),
            Self::NotAuthenticated => "Authentication is required.".to_string(),
            Self::SsoFailed => "Single sign-on authentication failed.".to_string(),
            Self::ExpiredToken => "Authentication token has expired.".to_string(),
            Self::InvalidToken => "Authentication token is invalid.".to_string(),
            Self::Forbidden => "The requested operation is not allowed.".to_string(),
            Self::NotFound => "The requested resource is not found.".to_string(),
            Self::ValidationFailed { .. } => "Request validation failed.".to_string(),
            Self::Conflict { message, .. } => message.clone(),
        }
    }

    #[must_use]
    pub fn details(&self) -> Option<serde_json::Value> {
        match self {
            Self::ValidationFailed { details } => Some(details.clone()),
            _ => None,
        }
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
