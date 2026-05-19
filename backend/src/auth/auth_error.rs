use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use thiserror::Error;

use crate::auth;
use crate::common;
use crate::db;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Internal server error {0}")]
    Internal(#[from] axum::http::Error),

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
        let err = match &self {
            Self::Internal(_) => common::ApiError::internal(),
            Self::PasswordHashingFailed(_) => common::ApiError::internal(),
            Self::DatabaseOperationFailed(_) => common::ApiError::internal(),
            Self::RequestHeaderOperationFailed(_) => common::ApiError::internal(),
            Self::InvalidCredentials => common::ApiError::invalid_credentials(),
            Self::SsoOperationFailed(_) => common::ApiError::not_authenticated(),
            Self::UserAlreadyExists => common::ApiError::user_already_exists(),
            Self::JwtOperationFailed(jwt_error) => jwt_error.into(),
            Self::InvalidToken(token_error) => token_error.into(),
        };
        if err.status == StatusCode::INTERNAL_SERVER_ERROR {
            auth::log_internal_error(&self, "auth");
        } else {
            auth::log_auth_rejection(&self);
        }
        err.into_response()
    }
}
