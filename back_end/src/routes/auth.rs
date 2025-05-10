use axum::{response::IntoResponse, http::StatusCode, Json};
use serde::Deserialize;
use serde_json::json;
use thiserror::Error;
use tower_sessions::Session;
use tower_sessions::session::Error as SessionLibError;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Failed to insert session data")]
    InsertSessionFailed(#[source] SessionLibError),

    #[error("Failed to read session data")]
    ReadSessionFailed(#[source] SessionLibError),

    #[error("Failed to flush session")]
    FlushSessionFailed(#[source] SessionLibError),
}

impl IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        // Log the error (self.to_string() will include source error message via thiserror)
        tracing::error!("{}", &self);

        let (status, error_message) = match self {
            Self::InvalidCredentials => (StatusCode::UNAUTHORIZED, self.to_string()),
            Self::InsertSessionFailed(_)  => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            Self::ReadSessionFailed(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            Self::FlushSessionFailed(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
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
        .map_err(AuthError::InsertSessionFailed)?;

    Ok(Json(json!({"result": "ok"})))
}

/// route to handle log out
#[allow(clippy::unused_async)]
pub async fn logout(session: Session) -> Result<impl IntoResponse, AuthError> {
    let user: String = session.get("user_id").await
        .map_err(AuthError::ReadSessionFailed)?
        .unwrap_or_default();

    tracing::info!("Logging out user: {:?}", user);

    // drop session
    session.flush().await
        .map_err(AuthError::FlushSessionFailed)?;

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
