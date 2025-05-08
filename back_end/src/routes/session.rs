// print out session

use axum::{response::IntoResponse, Json, http::StatusCode};
use serde_json::json;
use tower_sessions::Session;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("Session fetch error: {0}")]
    FetchError(String),
    
    #[error("Session not found")]
    NotFound,
}

impl IntoResponse for SessionError {
    fn into_response(self) -> axum::response::Response {
        let (status, error_message) = match self {
            Self::FetchError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            Self::NotFound => (StatusCode::NOT_FOUND, self.to_string()),
        };

        let body = Json(json!({
            "result": "error",
            "message": error_message
        }));

        (status, body).into_response()
    }
}

/// output entire session object
#[allow(clippy::unused_async)]
pub async fn handler(session: Session) -> Result<impl IntoResponse, SessionError> {
    tracing::info!("Seeking session info");
    Ok(Json(json!({ "session": format!("{:?}", session) })))
}

/// output session data in json
#[allow(clippy::unused_async)]
pub async fn data_handler(session: Session) -> Result<impl IntoResponse, SessionError> {
    tracing::info!("Seeking session data");
    let user_id = session.get_value("user_id").await
        .map_err(|err| {
            tracing::error!("Failed to get session data: {}", err);
            SessionError::FetchError(format!("Failed to get session data: {}", err))
        })?
        .unwrap_or_default();

    Ok(Json(json!({ "user_id": user_id })))
}
