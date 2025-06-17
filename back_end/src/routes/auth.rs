use argon2::Argon2;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::password_hash::rand_core::OsRng;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::Json;
use axum::response::IntoResponse;
use chrono::DateTime;
use serde::Deserialize;
use serde_json::json;
use thiserror::Error;

use crate::jwt;
use crate::jwt::{JwtError, TokenResponse};
use crate::store::StoreError;
use crate::appcontext::AppContext;
use crate::db::schema::NewRefreshToken;

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

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("JWT error: {0}")]
    JwtError(#[from] JwtError),

    #[error("Password hashing error: {0}")]
    PasswordHashingError(String),

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

/// Login route
pub async fn login(State(context): State<AppContext>, Json(login): Json<Login>) -> Result<impl IntoResponse, AuthError> {
    tracing::info!("Logging in user: {}", login.username);

    // Get user from database
    let user = context.store.get_user_by_username(&login.username).await
        .map_err(|_| AuthError::InvalidCredentials)?;

    verify_password(&login.password, user.password_hash)?;

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
#[allow(clippy::unused_async)]
pub async fn logout(State(context): State<AppContext>, req: Request<Body>) -> Result<impl IntoResponse, AuthError> {
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
pub async fn refresh_access_token(State(context): State<AppContext>, Json(request): Json<RefreshTokenRequest>) -> Result<impl IntoResponse, AuthError> {
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
pub async fn revoke_token(State(context): State<AppContext>, Json(request): Json<RevokeTokenRequest>) -> Result<impl IntoResponse, AuthError> {
    tracing::info!("Revoking refresh token");

    // Decode refresh token to get JTI
    let refresh_claims = jwt::decode_refresh_token(&context.config.jwt, &request.refresh_token)
        .map_err(|_| AuthError::TokenInvalid)?;

    // Revoke the token
    context.store.revoke_refresh_token(&refresh_claims.jti).await?;
    Ok(Json(json!({"result": "ok"})))
}

/// Hash a password using Argon2
pub fn hash_password(password: &str) -> Result<String, AuthError> {
    let salt = SaltString::generate(OsRng);
    let password_hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| AuthError::PasswordHashingError(e.to_string()))?
        .to_string();
    Ok(password_hash)
}

/// Verify a password against a hash
fn verify_password(password: &str, hash: Option<String>) -> Result<bool, AuthError> {
    // User has no password set (SSO only), cannot login with password
    let hash = hash.ok_or(AuthError::InvalidCredentials)?;
    let parsed_hash = PasswordHash::new(&hash).map_err(|e| AuthError::PasswordHashingError(e.to_string()))?;
    match Argon2::default().verify_password(password.as_bytes(), &parsed_hash) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(AuthError::PasswordHashingError(e.to_string())),
    }
}
