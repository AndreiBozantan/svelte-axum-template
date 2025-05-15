use std::sync::Arc;
use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;

use crate::auth_utils::{validate_jwt, Claims, create_jwt};
use crate::store::Store;

#[derive(Debug, Error)]
pub enum TokenError {
    #[error("Invalid or expired token")]
    InvalidToken,

    #[error("Failed to create JWT token")]
    TokenCreationFailed,

    #[error("Database error: {0}")]
    DatabaseError(String),
}

impl IntoResponse for TokenError {
    fn into_response(self) -> axum::response::Response {
        tracing::error!("{}", &self);

        let (status, error_message) = match self {
            Self::InvalidToken => (StatusCode::UNAUTHORIZED, self.to_string()),
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

#[derive(Deserialize)]
pub struct RefreshTokenRequest {
    refresh_token: String,
}

#[derive(Serialize)]
pub struct TokenResponse {
    result: String,
    access_token: String,
    refresh_token: Option<String>,
    expires_in: i64,
}

/// Route to refresh an expired JWT token using a refresh token
#[allow(clippy::unused_async)]
pub async fn refresh_token(
    State(store): State<Arc<Store>>, 
    Json(refresh_req): Json<RefreshTokenRequest>
) -> Result<impl IntoResponse, TokenError> {
    // Validate the refresh token
    let claims = validate_jwt(&refresh_req.refresh_token, &store.jwt_config)
        .map_err(|_| TokenError::InvalidToken)?;
    
    // Retrieve user details from DB to get tenant_id
    let user = store.get_user_by_username(&claims.sub).await
        .map_err(|e| TokenError::DatabaseError(e.to_string()))?;

    // Create new access token
    let access_claims = Claims::new(
        &claims.sub,
        user.tenant_id,
        store.jwt_config.access_token_expiry_mins,
    );
    
    let access_token = create_jwt(&access_claims, &store.jwt_config)
        .map_err(|_| TokenError::TokenCreationFailed)?;

    // Create new refresh token with longer expiration
    let refresh_claims = Claims::new(
        &claims.sub,
        user.tenant_id,
        store.jwt_config.refresh_token_expiry_mins,
    );
    
    let refresh_token = create_jwt(&refresh_claims, &store.jwt_config)
        .map_err(|_| TokenError::TokenCreationFailed)?;

    // Store the new token in the database with expiration
    let expires_at = Some(access_claims.exp);
    store.create_token(user.id, &access_token, expires_at).await
        .map_err(|e| TokenError::DatabaseError(e.to_string()))?;

    // Return tokens to the client
    Ok(Json(TokenResponse {
        result: "ok".to_string(),
        access_token,
        refresh_token: Some(refresh_token),
        expires_in: store.jwt_config.access_token_expiry_mins * 60, // convert to seconds
    }))
}

/// Route to revoke a token (logout from API)
#[allow(clippy::unused_async)]
pub async fn revoke_token(
    State(store): State<Arc<Store>>,
    Json(token_req): Json<RefreshTokenRequest>,
) -> Result<impl IntoResponse, TokenError> {
    // Delete the token from the database
    store.delete_token(&token_req.refresh_token).await
        .map_err(|e| TokenError::DatabaseError(e.to_string()))?;

    Ok(Json(json!({"result": "ok"})))
}
