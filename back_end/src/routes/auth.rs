use axum::{response::IntoResponse, http::StatusCode, Json, extract::State};
use chrono::{DateTime};
use serde::Deserialize;
use serde_json::json;
use thiserror::Error;
use tower_sessions::Session;
use tower_sessions::session::Error as SessionLibError;

use crate::jwt;
use crate::jwt::{JwtError, TokenResponse};
use crate::password::{verify_password, PasswordError};
use crate::store::StoreError;
use crate::state::AppState;
use crate::db::schema::NewRefreshToken;

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

    #[error("JWT error: {0}")]
    JwtError(#[from] JwtError),

    #[error("Password hashing error: {0}")]
    PasswordError(#[from] PasswordError),

    #[error("Database error: {0}")]
    DatabaseError(#[from] StoreError),

    #[error("User not found")]
    UserNotFound,

    #[error("Token expired or invalid")]
    TokenInvalid,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        tracing::error!(
            error_type = %std::any::type_name::<Self>(),
            error_subtype = %std::any::type_name_of_val(&self),
            error_message = %self);

        let (status, error_message) = match self {
            Self::InvalidCredentials => (StatusCode::UNAUTHORIZED, self.to_string()),
            Self::InsertSessionFailed(_)  => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            Self::ReadSessionFailed(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            Self::FlushSessionFailed(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            Self::JwtError(_) => (StatusCode::UNAUTHORIZED, self.to_string()),
            Self::PasswordError(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            Self::DatabaseError(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            Self::UserNotFound => (StatusCode::NOT_FOUND, self.to_string()),
            Self::TokenInvalid => (StatusCode::UNAUTHORIZED, self.to_string()),
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
    State(app_state): State<AppState>,
    Json(login): Json<Login>)
-> Result<impl IntoResponse, AuthError>
{
    tracing::info!("Logging in user: {}", login.username);

    // Get user from database
    let user = app_state.store.get_user_by_username(&login.username).await
        .map_err(|_| AuthError::InvalidCredentials)?;

    // Verify password (only for non-SSO users)
    match &user.password_hash {
        Some(hash) => {
            if !verify_password(&login.password, hash)? {
                return Err(AuthError::InvalidCredentials);
            }
        },
        None => {
            // User has no password set (SSO only), cannot login with password
            return Err(AuthError::InvalidCredentials);
        }
    }

    // Generate JWT tokens with appropriate expiration
    let access_token = jwt::generate_access_token(
        &app_state.config.jwt,
        user.id,
        &user.username,
        user.tenant_id
    )?;

    let refresh_token = jwt::generate_refresh_token(
        &app_state.config.jwt,
        user.id)?;

    // Store refresh token in database
    let refresh_claims = jwt::decode_refresh_token(&app_state.config.jwt, &refresh_token)?;
    let expires_at = DateTime::from_timestamp(refresh_claims.exp, 0).ok_or(AuthError::TokenInvalid)?;
    let token_hash = format!("{:x}", md5::compute(&refresh_token)); // Simple hash for storage

    let new_refresh_token = NewRefreshToken {
        jti: refresh_claims.jti,
        user_id: user.id,
        token_hash: token_hash,
        expires_at: expires_at.naive_utc(),
    };

    app_state.store.store_refresh_token(new_refresh_token).await?;

    // Also store in session for backward compatibility
    session.insert("user_id", user.username.clone()).await
        .map_err(AuthError::InsertSessionFailed)?;    // Calculate actual refresh token expiry based on client type

    let token_response = TokenResponse::new(
        access_token,
        refresh_token,
        app_state.config.jwt.access_token_expiry,
        app_state.config.jwt.refresh_token_expiry,
    );

    Ok(Json(json!({
        "result": "ok",
        "tokens": token_response,
        "user": {
            "id": user.id,
            "username": user.username,
            "tenant_id": user.tenant_id
        }
    })))
}

/// route to handle log out
#[allow(clippy::unused_async)]
pub async fn logout(
    session: Session,
    State(app_state): State<AppState>)
-> Result<impl IntoResponse, AuthError>
{
    let user: String = session.get("user_id").await
        .map_err(AuthError::ReadSessionFailed)?
        .unwrap_or_default();

    tracing::info!("Logging out user: {:?}", user);    // If we have a user session, revoke all their refresh tokens
    if !user.is_empty() {
        if let Ok(db_user) = app_state.store.get_user_by_username(&user).await {
            let _ = app_state.store.revoke_all_user_refresh_tokens(db_user.id).await;
        }
    }

    // Drop session
    session.flush().await
        .map_err(AuthError::FlushSessionFailed)?;

    Ok(Json(json!({"result": "ok"})))
}

/// Route to refresh access token using refresh token
pub async fn refresh_token(
    State(app_state): State<AppState>,
    Json(request): Json<RefreshTokenRequest>)
-> Result<impl IntoResponse, AuthError>
{
    tracing::info!("Refreshing access token");

    // Decode and validate refresh token
    let refresh_claims = jwt::decode_refresh_token(&app_state.config.jwt, &request.refresh_token)
        .map_err(|_| AuthError::TokenInvalid)?;    // Check if refresh token exists in database and is not revoked
    let stored_token = app_state.store.get_refresh_token_by_jti(&refresh_claims.jti).await
        .map_err(|_| AuthError::TokenInvalid)?;

    // Verify token hash
    let token_hash = format!("{:x}", md5::compute(&request.refresh_token));
    if stored_token.token_hash != token_hash {
        return Err(AuthError::TokenInvalid);
    }

    // Get user details
    let user = app_state.store.get_user_by_id(stored_token.user_id).await?;

    // Generate new access token
    let new_access_token = jwt::generate_access_token(
        &app_state.config.jwt,
        user.id,
        &user.username,
        user.tenant_id,
    )?;    Ok(Json(json!({
        "result": "ok",
        "access_token": new_access_token,
        "expires_in": app_state.config.jwt.access_token_expiry,
        "user": {
            "id": user.id,
            "username": user.username,
            "tenant_id": user.tenant_id
        }
    })))
}

/// Route to revoke a refresh token
pub async fn revoke_token(
    State(app_state): State<AppState>,
    Json(request): Json<RevokeTokenRequest>)
-> Result<impl IntoResponse, AuthError>
{
    tracing::info!("Revoking refresh token");

    // Decode refresh token to get JTI
    let refresh_claims = jwt::decode_refresh_token(&app_state.config.jwt, &request.refresh_token)
        .map_err(|_| AuthError::TokenInvalid)?;

    // Revoke the token
    app_state.store.revoke_refresh_token(&refresh_claims.jti).await?;    Ok(Json(json!({"result": "ok"})))
}

#[derive(Deserialize)]
pub struct Login {
    username: String,
    password: String,
}

#[derive(Deserialize)]
pub struct RefreshTokenRequest {
    refresh_token: String,
}

#[derive(Deserialize)]
pub struct RevokeTokenRequest {
    refresh_token: String,
}
