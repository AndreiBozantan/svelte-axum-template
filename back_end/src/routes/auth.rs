use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::Json;
use axum::response::IntoResponse;
use chrono::DateTime;
use serde::Deserialize;
use serde_json::json;
use thiserror::Error;

use crate::app;
use crate::auth;
use crate::auth::jwt;
use crate::auth::jwt::{JwtError, TokenResponse};
use crate::db::StoreError;
use crate::db::schema::NewRefreshToken;

#[derive(Deserialize)]
pub struct Login {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct RefreshTokenRequest {
    refresh_token: String,
}

#[derive(Deserialize)]
pub struct RevokeTokenRequest {
    refresh_token: String,
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("JWT error: {0}")]
    JwtError(#[from] JwtError),

    #[error("Password error: {0}")]
    PasswordHashingError(#[from] argon2::password_hash::Error),

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
            Self::JwtError(_) => (StatusCode::UNAUTHORIZED, self.to_string()),
            Self::PasswordHashingError(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            Self::DatabaseError(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            Self::UserNotFound => (StatusCode::UNAUTHORIZED, self.to_string()),
            Self::TokenInvalid => (StatusCode::UNAUTHORIZED, self.to_string()),
        };

        let body = Json(json!({
            "result": "error",
            "message": error_message
        }));

        (status, body).into_response()
    }
}

/// Login route
pub async fn login(State(context): State<app::Context>, Json(login): Json<Login>) -> Result<impl IntoResponse, AuthError> {
    tracing::info!("Logging in user: {}", login.username);

    // Get user from database
    let user = context.store.get_user_by_username(&login.username).await
        .map_err(|_| AuthError::UserNotFound)?;

    if !auth::verify_password(&login.password, user.password_hash)? {
        tracing::warn!("Invalid password for user: {}", login.username);
        return Err(AuthError::InvalidCredentials);
    }

    // Generate JWT tokens with appropriate expiration
    let access_token = jwt::generate_access_token(
        &context.config.jwt,
        user.id,
        &user.username,
        user.tenant_id)?;

    let refresh_token = jwt::generate_refresh_token(
        &context.config.jwt,
        user.id)?;

    // store refresh token in database
    let refresh_claims = jwt::decode_refresh_token(&context.config.jwt, &refresh_token)?;
    let expires_at = DateTime::from_timestamp(refresh_claims.exp, 0).ok_or(AuthError::TokenInvalid)?;
    let token_hash = format!("{:x}", md5::compute(&refresh_token)); // simple hash for storage
    let new_refresh_token = NewRefreshToken {
        jti: refresh_claims.jti,
        user_id: user.id,
        token_hash: token_hash,
        expires_at: expires_at.naive_utc(),
    };
    context.store.store_refresh_token(new_refresh_token).await?;

    let token_response = TokenResponse::new(access_token, refresh_token, &context.config.jwt);
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

/// Logout route
pub async fn logout(State(context): State<app::Context>, req: Request<Body>) -> Result<impl IntoResponse, AuthError> {
    let claims = jwt::decode_access_token_from_req(&context.config.jwt, &req)?;
    tracing::info!(user_id = claims.sub, username = claims.username, "Logout");

    // revoke all the associated refresh tokens
    let user_id = claims.sub.parse::<i64>().map_err(|_| AuthError::TokenInvalid)?;
    if let Ok(db_user) = context.store.get_user_by_id(user_id).await {
        let _ = context.store.revoke_all_user_refresh_tokens(db_user.id).await;
    }

    Ok(Json(json!({"result": "ok"})))
}

/// Route to refresh access token using refresh token
pub async fn refresh_access_token(State(context): State<app::Context>, Json(request): Json<RefreshTokenRequest>) -> Result<impl IntoResponse, AuthError> {
    tracing::info!("Refreshing access token");

    // Decode and validate refresh token
    let refresh_claims = jwt::decode_refresh_token(&context.config.jwt, &request.refresh_token)
        .map_err(|_| AuthError::TokenInvalid)?;    // Check if refresh token exists in database and is not revoked
    let stored_token = context.store.get_refresh_token_by_jti(&refresh_claims.jti).await
        .map_err(|_| AuthError::TokenInvalid)?;

    // Verify token hash
    let token_hash = format!("{:x}", md5::compute(&request.refresh_token));
    if stored_token.token_hash != token_hash {
        return Err(AuthError::TokenInvalid);
    }

    // Generate new access token for the user
    let user = context.store.get_user_by_id(stored_token.user_id).await?;
    let new_access_token = jwt::generate_access_token(
        &context.config.jwt,
        user.id,
        &user.username,
        user.tenant_id,
    )?;

    Ok(Json(json!({
        "result": "ok",
        "access_token": new_access_token,
        "expires_in": context.config.jwt.access_token_expiry,
        "user": {
            "id": user.id,
            "username": user.username,
            "tenant_id": user.tenant_id
        }
    })))
}

/// Route to revoke a refresh token
pub async fn revoke_token(State(context): State<app::Context>, Json(request): Json<RevokeTokenRequest>) -> Result<impl IntoResponse, AuthError> {
    tracing::info!("Revoking refresh token");

    // Decode refresh token to get JTI
    let refresh_claims = jwt::decode_refresh_token(&context.config.jwt, &request.refresh_token)
        .map_err(|_| AuthError::TokenInvalid)?;

    // Revoke the token
    context.store.revoke_refresh_token(&refresh_claims.jti).await?;
    Ok(Json(json!({"result": "ok"})))
}
