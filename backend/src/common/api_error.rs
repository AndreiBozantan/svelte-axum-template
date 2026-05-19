use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct ApiError {
    #[serde(skip)]
    pub status: StatusCode,

    pub code: &'static str,

    pub message: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
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
