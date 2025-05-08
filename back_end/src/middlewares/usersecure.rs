use axum::{
    body::Body,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;
use tower_sessions::Session;

#[derive(Debug, Error)]
pub enum UserSecureError {
    #[error("Session error: {0}")]
    SessionError(String),

    #[error("Unauthorized: user not authenticated")]
    Unauthorized,
}

impl IntoResponse for UserSecureError {
    fn into_response(self) -> axum::response::Response {
        let (status, error_message) = match self {
            Self::SessionError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, self.to_string()),
        };

        let body = Json(json!({
            "result": "error",
            "message": error_message
        }));

        (status, body).into_response()
    }
}

/// Middleware to validate user authentication from session data
pub async fn user_secure(
    session: Session,
    req: Request<Body>,
    next: Next,
) -> Result<Response, UserSecureError> {
    tracing::info!("Middleware: checking if user exists");

    let user_id = session
        .get_value("user_id")
        .await
        .map_err(|e| {
            tracing::error!("Session error: {}", e);
            UserSecureError::SessionError(format!("Failed to get session data: {}", e))
        })?
        .ok_or_else(|| {
            tracing::debug!("User not authenticated");
            UserSecureError::Unauthorized
        })?;

    tracing::debug!("user_id Extracted: {}", user_id);

    // accepts all user but you could add a check here to match user access
    Ok(next.run(req).await)
}
