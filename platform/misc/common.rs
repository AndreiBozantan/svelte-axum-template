use axum::Json;
use axum::response::Response;
use axum::response::IntoResponse;
use reqwest::StatusCode;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;

use crate::common;
use crate::config;
use crate::db;
use crate::jwt;
use crate::logger;
use crate::tokens;
use crate::sso;

pub type ArcContext = std::sync::Arc<Context>;
pub type AppContext = axum::extract::State<ArcContext>;

#[derive(Debug, Serialize)]
pub struct ApiError {
    #[serde(skip)]
    pub status: StatusCode,

    pub code: &'static str,

    pub message: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

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
    JwtOperationFailed(#[from] jwt::JwtError),

    #[error("Password hashing failed: {0}")]
    PasswordHashingFailed(#[from] argon2::password_hash::Error),

    #[error("Token expired or invalid")]
    InvalidToken(#[from] tokens::TokenError),

    #[error("User already exists")]
    UserAlreadyExists,

    #[error("SSO operation failed: {0}")]
    SsoOperationFailed(#[from] sso::SsoError),
}

#[derive(Clone)]
pub struct Context {
    pub env: String,
    pub db: db::SqlContext,
    pub jwt: jwt::JwtContext,
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
    50
}

impl Context {
    #[must_use]
    pub fn new(
        db: db::SqlContext,
        jwt: jwt::JwtContext,
        settings: config::AppSettings,
        http_client: reqwest::Client,
    ) -> Self {
        let env = config::AppSettings::get_app_run_env(&settings.server.env_vars_prefix);
        Self {
            env,
            db,
            jwt,
            settings,
            http_client,
        }
    }

    #[must_use]
    pub fn is_prod_env(&self) -> bool {
        self.env == "production"
    }

    #[must_use]
    pub fn is_dev_env(&self) -> bool {
        self.env == "development"
    }

    #[must_use]
    pub fn is_test_env(&self) -> bool {
        self.env == "test"
    }
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
            logger::log_internal_error(&self, "auth");
        } else {
            logger::log_auth_rejection(&self);
        }
        err.into_response()
    }
}


impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            details: None,
        }
    }

    #[must_use]
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }

    #[must_use]
    pub fn internal() -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "An unexpected error occured.",
        )
    }

    #[must_use]
    pub fn invalid_credentials() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
            "Email or password is incorrect",
        )
    }

    #[must_use]
    pub fn not_authenticated() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "not_authenticated",
            "Authentication is required.",
        )
    }

    #[must_use]
    pub fn sso_failed() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "sso_failed",
            "Single sign-on authentication failed.",
        )
    }

    #[must_use]
    pub fn expired_token() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "expired_token",
            "Authentication token has expired.",
        )
    }

    #[must_use]
    pub fn invalid_token() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "Authentication token is invalid.",
        )
    }

    #[must_use]
    pub fn forbidden() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "forbidden",
            "The requested operation is not allowed.",
        )
    }

    #[must_use]
    pub fn not_found() -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "not_found",
            "The requested resource is not found.",
        )
    }

    #[must_use]
    pub fn validation_failed(details: serde_json::Value) -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "validation_failed",
            "Request validation failed.",
        )
        .with_details(details)
    }

    #[must_use]
    pub fn user_already_exists() -> Self {
        Self::conflict("user_already_exists", "A user with the given email already exists.")
    }

    #[must_use]
    pub fn conflict(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, code, message)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status;
        (status, Json(self)).into_response()
    }
}
