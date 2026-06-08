use axum::Json;
use axum::response::IntoResponse;
use axum::response::Response;
use reqwest::StatusCode;
use serde::Deserialize;
use serde::Serialize;

use crate::common;
use crate::jwt;

#[derive(Debug, Clone, thiserror::Error, Serialize)]
#[error("{message}")]
pub struct Error {
    #[serde(skip)]
    status: StatusCode,
    code: &'static str,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<serde_json::Value>,
}

impl Error {
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

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let status = self.status;
        (status, Json(self)).into_response()
    }
}

impl From<jwt::Error> for Error {
    fn from(error: jwt::Error) -> Self {
        tracing::error!("JWT error: {error}");
        match error {
            jwt::Error::TokenExpired => Self::expired_token(),
            jwt::Error::InvalidToken => Self::invalid_token(),
            _ => Self::internal(),
        }
    }
}

impl From<common::RepoError> for Error {
    fn from(error: common::RepoError) -> Self {
        // TODO: use structured logging here
        tracing::error!("database error: {error}");

        #[allow(clippy::match_same_arms)]
        match error {
            common::RepoError::RowNotFound => Self::not_found(),
            common::RepoError::UniqueViolation(_) => Self::db_key_violation("unique_violation"),
            common::RepoError::ForeignKeyViolation(_) => Self::db_key_violation("foreign_key_violation"),
            common::RepoError::CheckViolation(_) => Self::db_key_violation("check_violation"),
            common::RepoError::Database(_) => Self::internal(),
            common::RepoError::RowConversionFailed(_) => Self::internal(),
        }
    }
}

impl From<common::DataValidationError> for Error {
    fn from(error: common::DataValidationError) -> Self {
        match error {
            common::DataValidationError::InvalidEmail => Self::invalid_credentials(),
        }
    }
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

impl Pagination {
    #[must_use]
    pub fn sanitize(&self) -> (i64, i64) {
        let limit = self.limit.clamp(1, 200);
        let offset = self.offset.max(0);
        (limit, offset)
    }
}
