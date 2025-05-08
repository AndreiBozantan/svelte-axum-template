use axum::{response::IntoResponse, http::StatusCode, Json};
use serde_json::json;
use thiserror::Error;
use tower_sessions::Session;
use tower_sessions::session::Error as SessionLibError;

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("Failed to fetch session data")]
    FetchError(#[source] SessionLibError),

    #[error("Session value not found")]
    ValueNotFound,

    #[error("Session not found")]
    SessionNotFound,
}

impl IntoResponse for SessionError {
    fn into_response(self) -> axum::response::Response {
        tracing::error!("{}", &self);

        let (status, error_message) = match self {
            Self::FetchError(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            Self::ValueNotFound => (StatusCode::NOT_FOUND, self.to_string()),
            Self::SessionNotFound => (StatusCode::NOT_FOUND, self.to_string()),
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
    let user_id: String = session.get("user_id").await
        .map_err(SessionError::FetchError)?
        .ok_or(SessionError::ValueNotFound)?;

    Ok(Json(json!({ "user_id": user_id })))
}
