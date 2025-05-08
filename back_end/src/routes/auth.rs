use axum::{response::IntoResponse, Json, http::StatusCode};
use serde::Deserialize;
use serde_json::json;
use tower_sessions::Session;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Session error: {0}")]
    SessionError(String),
}

impl IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        let (status, error_message) = match self {
            Self::InvalidCredentials => (StatusCode::UNAUTHORIZED, self.to_string()),
            Self::SessionError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };

        let body = Json(json!({
            "result": "error",
            "message": error_message
        }));

        (status, body).into_response()
    }
}

/// route to handle log in
#[allow(clippy::unused_async)]
pub async fn login(session: Session, Json(login): Json<Login>) -> Result<impl IntoResponse, AuthError> {
    tracing::info!("Logging in user: {}", login.username);

    if !check_password(&login.username, &login.password) {
        return Err(AuthError::InvalidCredentials);
    }

    session.insert("user_id", login.username).await
        .map_err(|err| {
            tracing::error!("Failed to insert session data: {}", err);
            AuthError::SessionError(format!("Failed to insert session data: {}", err))
        })?;

    Ok(Json(json!({"result": "ok"})))
}

/// route to handle log out
#[allow(clippy::unused_async)]
pub async fn logout(session: Session) -> Result<impl IntoResponse, AuthError> {
    let user = session.get_value("user_id").await
        .map_err(|err| {
            tracing::error!("Failed to read session data: {}", err);
            AuthError::SessionError(format!("Failed to read session data: {}", err))
        })?
        .unwrap_or_default();

    tracing::info!("Logging out user: {:?}", user);

    // drop session
    session.flush().await
        .map_err(|err| {
            tracing::error!("Failed to flush session: {}", err);
            AuthError::SessionError(format!("Failed to flush session: {}", err))
        })?;

    Ok(Json(json!({"result": "ok"})))
}

// assume all passwords work
const fn check_password(_username: &str, _password: &str) -> bool {
    true
}

#[derive(Deserialize)]
pub struct Login {
    username: String,
    password: String,
}
