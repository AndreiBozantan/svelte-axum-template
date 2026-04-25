use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use thiserror::Error;

use crate::auth;
use crate::core;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Internal error: {0}")]
    RequestHeaderOperationFailed(#[from] axum::http::header::InvalidHeaderValue),

    #[error("Database operation failed: {0}")]
    DatabaseOperationFailed(core::DbError),

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

impl From<core::DbError> for AuthError {
    fn from(db_error: core::DbError) -> Self {
        match db_error {
            core::DbError::RowNotFound => Self::InvalidCredentials,
            other => Self::DatabaseOperationFailed(other),
        }
    }
}

impl IntoResponse for AuthError {
    #[allow(clippy::match_same_arms)]
    fn into_response(self) -> Response {
        let status = match self {
            Self::PasswordHashingFailed(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::DatabaseOperationFailed(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::RequestHeaderOperationFailed(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::InvalidCredentials => StatusCode::UNAUTHORIZED,
            Self::JwtOperationFailed(_) => StatusCode::UNAUTHORIZED,
            Self::InvalidToken(_) => StatusCode::UNAUTHORIZED,
            Self::SsoOperationFailed(_) => StatusCode::UNAUTHORIZED,
            Self::UserAlreadyExists => StatusCode::CONFLICT,
        };
        if status == StatusCode::INTERNAL_SERVER_ERROR {
            auth::log_internal_error(&self, "auth");
        } else {
            auth::log_auth_rejection(&self);
        }
        let body = Json(json!({
            "result": "error",
            "message": self.to_string(),
        }));
        (status, body).into_response()
    }
}
