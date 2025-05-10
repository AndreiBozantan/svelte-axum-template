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
use tower_sessions::session::Error as SessionLibError;

#[derive(Debug, Error)]
pub enum UserSecureError {
    #[error("Failed to query session data")]
    SessionQueryFailed(#[source] SessionLibError),

    #[error("Unauthorized: user not authenticated")]
    Unauthorized,
}

impl IntoResponse for UserSecureError {
    fn into_response(self) -> axum::response::Response {
        tracing::error!("{}", &self);

        let (status, error_message) = match self {
            Self::SessionQueryFailed(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
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

    let user_id: String = session
        .get("user_id")
        .await
        .map_err(UserSecureError::SessionQueryFailed)?
        .ok_or(UserSecureError::Unauthorized)?;

    tracing::debug!("user_id Extracted: {}", user_id);

    // accepts all user but you could add a check here to match user access
    Ok(next.run(req).await)
}
