use axum::Json;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::response::IntoResponse;
use chrono::DateTime;
use serde::Deserialize;
use serde_json::json;
use sha2::Digest;
use thiserror::Error;

use crate::auth;
use crate::core;
use crate::db;
use crate::services::{audit, sso};

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

    #[error("JWT operation failed: {0}")]
    JwtOperationFailed(#[from] auth::JwtError),

    #[error("Password hashing failed: {0}")]
    PasswordHashingFailed(#[from] argon2::password_hash::Error),

    #[error("Token expired or invalid")]
    TokenInvalid,

    #[error("User not found")]
    UserNotFound,

    #[error("Database operation failed: {0}")]
    DatabaseOperationFailed(core::DbError),

    #[error("OAuth operation failed: {0}")]
    OAuthOperationFailed(#[from] sso::Error),
}

impl From<core::DbError> for AuthError {
    fn from(db_error: core::DbError) -> Self {
        match db_error {
            core::DbError::RowNotFound => Self::InvalidCredentials,
            other => Self::DatabaseOperationFailed(other),
        }
    }
}

impl IntoResponse for AuthError {
    #[allow(clippy::match_same_arms)]
    fn into_response(self) -> axum::response::Response {
        audit::log_auth_error(&self);
        let status = match self {
            Self::PasswordHashingFailed(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::DatabaseOperationFailed(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::InvalidCredentials => StatusCode::UNAUTHORIZED,
            Self::JwtOperationFailed(_) => StatusCode::UNAUTHORIZED,
            Self::UserNotFound => StatusCode::UNAUTHORIZED,
            Self::TokenInvalid => StatusCode::UNAUTHORIZED,
            Self::OAuthOperationFailed(_) => StatusCode::UNAUTHORIZED,
        };
        let body = Json(json!({
            "result": "error",
            "message": self.to_string(),
        }));
        (status, body).into_response()
    }
}

/// Login route
pub async fn login(
    State(context): State<core::ArcContext>,
    headers: HeaderMap,
    Json(login): Json<Login>,
) -> Result<impl IntoResponse, AuthError> {
    audit::log_user_login(&headers, &login.username);

    // Get user from database
    let user = db::get_user_by_name(&context.db, &login.username).await?;
    if !auth::verify_password(&login.password, user.password_hash)? {
        audit::log_invalid_password(&headers, &login.username);
        return Err(AuthError::InvalidCredentials);
    }

    // Generate JWT tokens with appropriate expiration
    let access_token = auth::generate_access_token(&context.jwt, user.id, &user.username, user.tenant_id)?;
    let refresh_token = auth::generate_refresh_token(&context.jwt, user.id)?;

    // store refresh token in database
    let refresh_claims = auth::decode_refresh_token(&context.jwt, &refresh_token)?;
    let expires_at = DateTime::from_timestamp(refresh_claims.exp, 0).ok_or(AuthError::TokenInvalid)?;
    let token_hash = get_token_hash_as_hex(&refresh_token);
    let new_refresh_token = db::NewRefreshToken {
        jti: refresh_claims.jti,
        user_id: user.id,
        token_hash,
        expires_at: expires_at.naive_utc(),
    };
    db::create_refresh_token(&context.db, new_refresh_token).await?;

    let token_response = auth::TokenResponse::new(&context.jwt, access_token, refresh_token);
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
pub async fn logout(
    State(context): State<core::ArcContext>,
    req: Request<Body>,
) -> Result<impl IntoResponse, AuthError> {
    let claims = auth::decode_access_token_from_req(&context.jwt, &req)?;
    audit::log_user_logout(req.headers(), &claims.sub, &claims.username);

    // revoke all the associated refresh tokens
    let user_id = claims.sub.parse::<i64>().map_err(|_| AuthError::TokenInvalid)?;
    if let Ok(db_user) = db::get_user_by_id(&context.db, user_id).await {
        let _ = db::revoke_all_refresh_tokens_for_user(&context.db, db_user.id).await;
    }

    Ok(Json(json!({"result": "ok"})))
}

/// Route to refresh access token using refresh token
pub async fn refresh_access_token(
    State(context): State<core::ArcContext>,
    headers: HeaderMap,
    Json(request): Json<RefreshTokenRequest>,
) -> Result<impl IntoResponse, AuthError> {
    // decode refresh token and check if it exists in database and is not revoked
    let refresh_claims = auth::decode_refresh_token(&context.jwt, &request.refresh_token)?;
    let stored_token = db::get_refresh_token_by_jti(&context.db, &refresh_claims.jti).await?;
    let token_hash = get_token_hash_as_hex(&request.refresh_token); // verify token hash
    if stored_token.token_hash != token_hash {
        return Err(AuthError::TokenInvalid);
    }

    // generate new access token for the user
    let user = db::get_user_by_id(&context.db, stored_token.user_id).await?;
    let new_access_token = auth::generate_access_token(&context.jwt, user.id, &user.username, user.tenant_id)?;
    audit::log_token_refresh(&headers, user.id, &refresh_claims.jti, &refresh_claims.sub);

    Ok(Json(json!({
        "result": "ok",
        "access_token": new_access_token,
        "expires_in": context.settings.jwt.access_token_expiry_minutes * 60,
        "user": {
            "id": user.id,
            "username": user.username,
            "tenant_id": user.tenant_id
        }
    })))
}

/// Route to revoke a refresh token
pub async fn revoke_token(
    State(context): State<core::ArcContext>,
    headers: HeaderMap,
    Json(request): Json<RevokeTokenRequest>,
) -> Result<impl IntoResponse, AuthError> {
    // decode refresh token to get JTI
    let refresh_claims = auth::decode_refresh_token(&context.jwt, &request.refresh_token)?;
    db::revoke_refresh_token(&context.db, &refresh_claims.jti).await?; // revoke the token
    audit::log_token_revoke(&headers, &refresh_claims.jti, &refresh_claims.sub);
    Ok(Json(json!({"result": "ok"})))
}

/// Handler for initiating Google OAuth flow
pub async fn google_auth_init(
    State(context): State<core::ArcContext>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<impl IntoResponse, AuthError> {
    let redirect_url = params.get("redirect_url");
    audit::log_oauth_flow_initiated("google", &headers, &redirect_url);
    let (auth_url, state) = sso::get_google_auth_url(&context, redirect_url).await?;
    audit::log_oauth_redirecting("google", &headers, &auth_url, &state);
    Ok(axum::response::Redirect::to(auth_url.as_str()))
}

/// Handler for Google OAuth callback
pub async fn google_auth_callback(
    State(context): State<core::ArcContext>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<sso::AuthRequest>,
) -> Result<impl IntoResponse, AuthError> {
    let (user_info, redirect_url) = sso::get_google_user_info(&context, &params.code, &params.state).await?;
    audit::log_oauth_callback_received("google", &headers, &params.state);

    if !user_info.verified_email {
        audit::log_oauth_security_violation("unverified_email", &headers, &user_info.email, &params.state);
        return Err(AuthError::InvalidCredentials);
    }

    // check if user already exists
    let existing_user = db::get_user_by_sso_id(&context.db, "google", &user_info.id).await;
    let user = match existing_user {
        Ok(user) => Ok(user),
        Err(core::DbError::RowNotFound) => {
            Ok(create_sso_user(&context, &user_info, "google", &headers, &params.state).await?)
        }
        Err(e) => Err(AuthError::DatabaseOperationFailed(e)),
    }?;

    audit::log_oauth_user_authenticated("google", &headers, &user_info.email, &params.state);

    // Generate JWT tokens for the user (same as regular login)
    let access_token = auth::generate_access_token(&context.jwt, user.id, &user.username, user.tenant_id)?;
    let refresh_token = auth::generate_refresh_token(&context.jwt, user.id)?;

    // Store refresh token in database
    let refresh_claims = auth::decode_refresh_token(&context.jwt, &refresh_token)?;
    let expires_at = chrono::DateTime::from_timestamp(refresh_claims.exp, 0).ok_or(auth::JwtError::InvalidToken)?;
    let token_hash = get_token_hash_as_hex(&refresh_token);
    let new_refresh_token = db::NewRefreshToken {
        jti: refresh_claims.jti,
        user_id: user.id,
        token_hash,
        expires_at: expires_at.naive_utc(),
    };
    db::create_refresh_token(&context.db, new_refresh_token).await?;

    let jwt_token_response = auth::TokenResponse::new(&context.jwt, access_token, refresh_token);

    // use provided redirect URL or default TODO: replace hardcoded URL
    let final_redirect_url = redirect_url.unwrap_or_else(|| "http://localhost:5173/login".to_string());

    // TODO: !!!! don't put the tokens in the URL
    let redirect_url_with_tokens = format!(
        "{}?oauth_success=true&access_token={}&refresh_token={}",
        final_redirect_url, jwt_token_response.access_token, jwt_token_response.refresh_token
    );

    Ok(axum::response::Redirect::to(&redirect_url_with_tokens))
}

async fn create_sso_user(
    context: &core::ArcContext,
    user_info: &sso::GoogleUserInfo,
    provider: &str,
    headers: &HeaderMap,
    state: &str,
) -> Result<db::User, AuthError> {
    audit::log_oauth_create_new_user(provider, headers, &user_info.email, state);

    // Check if email is already in use by a non-SSO user
    if let Ok(_existing_user) = db::get_user_by_email(&context.db, &user_info.email).await {
        audit::log_oauth_security_violation("email_already_exists", headers, &user_info.email, state);
        return Err(AuthError::InvalidCredentials);
    }

    let new_user = db::NewUser {
        username: user_info.email.clone(), // use email as username for SSO users
        password_hash: None,               // no password for SSO users
        email: Some(user_info.email.clone()),
        tenant_id: None, // TODO: !!! how to assign to a tenant???
        sso_provider: Some(provider.to_string()),
        sso_id: Some(user_info.id.clone()),
    };

    db::create_user(&context.db, new_user).await.map_err(AuthError::from)
}

fn get_token_hash_as_hex(token: &str) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(token);
    format!("{:x}", hasher.finalize())
}
