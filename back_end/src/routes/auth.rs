use axum::{response::IntoResponse, http::StatusCode, Json, extract::State};
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;
use tower_sessions::Session;
use tower_sessions::session::Error as SessionLibError;
use std::sync::Arc;
use crate::store::Store;
use crate::auth_utils::{Claims, create_jwt};

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
    
    #[error("User not found")]
    UserNotFound,
    
    #[error("Failed to create JWT token")]
    TokenCreationFailed,
    
    #[error("Database error: {0}")]
    DatabaseError(String),
}

impl IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        // Log the error (self.to_string() will include source error message via thiserror)
        tracing::error!("{}", &self);

        let (status, error_message) = match self {
            Self::InvalidCredentials => (StatusCode::UNAUTHORIZED, self.to_string()),
            Self::InsertSessionFailed(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            Self::ReadSessionFailed(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            Self::FlushSessionFailed(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            Self::UserNotFound => (StatusCode::NOT_FOUND, self.to_string()),
            Self::TokenCreationFailed => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            Self::DatabaseError(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
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
pub async fn login(
    session: Session,
    State(store): State<Arc<Store>>,
    Json(login): Json<Login>
) -> Result<impl IntoResponse, AuthError> {
    tracing::info!("Logging in user: {}", login.username);

    // Get user from database
    let user = store.get_user_by_username(&login.username).await
        .map_err(|e| match e {
            crate::store::StoreError::UserNotFound => AuthError::UserNotFound,
            _ => AuthError::DatabaseError(e.to_string()),
        })?;

    // Verify password
    if !crate::auth_utils::verify_password(&user.password_hash, &login.password) {
        return Err(AuthError::InvalidCredentials);
    }

    // Set user in session
    session.insert("user_id", login.username.clone()).await
        .map_err(AuthError::InsertSessionFailed)?;

    // Create JWT tokens (access and refresh)
    let access_claims = Claims::new(
        &login.username,
        user.tenant_id,
        store.jwt_config.access_token_expiry_mins,
    );
    
    let access_token = create_jwt(&access_claims, &store.jwt_config)
        .map_err(|_| AuthError::TokenCreationFailed)?;

    // Create refresh token with longer expiration
    let refresh_claims = Claims::new(
        &login.username,
        user.tenant_id,
        store.jwt_config.refresh_token_expiry_mins,
    );
    
    let refresh_token = create_jwt(&refresh_claims, &store.jwt_config)
        .map_err(|_| AuthError::TokenCreationFailed)?;

    // Store the token in the database with expiration for API access
    let expires_at = Some(access_claims.exp);
    store.create_token(user.id, &access_token, expires_at).await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

    // Return tokens to the client
    Ok(Json(TokenResponse {
        result: "ok".to_string(),
        access_token,
        refresh_token: Some(refresh_token),
        expires_in: store.jwt_config.access_token_expiry_mins * 60, // convert to seconds
    }))
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

#[derive(Deserialize)]
pub struct Login {
    username: String,
    password: String,
}

#[derive(Serialize)]
pub struct TokenResponse {
    result: String,
    access_token: String,
    refresh_token: Option<String>,
    expires_in: i64,
}
