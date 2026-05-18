use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use thiserror::Error;

use crate::auth;
use crate::common::constants;
use crate::db;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Internal error: {0}")]
    RequestHeaderOperationFailed(#[from] axum::http::header::InvalidHeaderValue),

    #[error("Database operation failed: {0}")]
    DatabaseOperationFailed(db::SqlError),

    #[error("JWT operation failed: {0}")]
    JwtOperationFailed(#[from] auth::JwtError),

    #[error("Password hashing failed: {0}")]
    PasswordHashingFailed(#[from] argon2::password_hash::Error),

    #[error("Token expired or invalid")]
    InvalidToken(#[from] auth::TokenError),

    #[error("User already exists")]
    UserAlreadyExists,

    #[error("SSO operation failed: {0}")]
    SsoOperationFailed(#[from] auth::SsoError),
}

impl From<db::SqlError> for AuthError {
    fn from(db_error: db::SqlError) -> Self {
        match db_error {
            db::SqlError::RowNotFound => Self::InvalidCredentials,
            other => Self::DatabaseOperationFailed(other),
        }
    }
}

impl IntoResponse for AuthError {
    #[allow(clippy::match_same_arms)]
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            Self::PasswordHashingFailed(_) => (StatusCode::INTERNAL_SERVER_ERROR, constants::err_msg::INTERNAL),
            Self::DatabaseOperationFailed(_) => (StatusCode::INTERNAL_SERVER_ERROR, constants::err_msg::INTERNAL),
            Self::RequestHeaderOperationFailed(_) => (StatusCode::INTERNAL_SERVER_ERROR, constants::err_msg::INTERNAL),
            Self::InvalidCredentials => (StatusCode::UNAUTHORIZED, constants::err_msg::INVALID_CREDENTIALS),
            Self::JwtOperationFailed(_) => (StatusCode::UNAUTHORIZED, constants::err_msg::INVALID_TOKEN),
            Self::InvalidToken(_) => (StatusCode::UNAUTHORIZED, constants::err_msg::INVALID_TOKEN),
            Self::SsoOperationFailed(_) => (StatusCode::UNAUTHORIZED, constants::err_msg::SSO_OPERATION_FAILED),
            Self::UserAlreadyExists => (StatusCode::CONFLICT, constants::err_msg::USER_ALREADY_EXISTS),
        };
        if status == StatusCode::INTERNAL_SERVER_ERROR {
            auth::log_internal_error(&self, "auth");
        } else {
            auth::log_auth_rejection(&self);
        }
        if let Self::JwtOperationFailed(e) = self {
            return e.into_response();
        }
        let body = Json(json!({
            "result": "error",
            "message": error_message
        }));

        (status, body).into_response()
    }
}
