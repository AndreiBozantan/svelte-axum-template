use axum::Json;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::response::IntoResponse;
use chrono::DateTime;
use serde::Deserialize;
use serde_json::json;
use sha2::Digest;
use thiserror::Error;

use crate::auth;
use crate::core;
use crate::db;

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
    OAuthOperationFailed(#[from] auth::OAuthError),
}

impl From<core::DbError> for AuthError {
    fn from(db_error: core::DbError) -> Self {
        match db_error {
            core::DbError::RowNotFound(_) => AuthError::InvalidCredentials,
            other => AuthError::DatabaseOperationFailed(other),
        }
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        tracing::error!(
            error_type = %std::any::type_name::<Self>(),
            error_subtype = %std::any::type_name_of_val(&self),
            error_message = %self);

        let (status, error_message) = match self {
            Self::PasswordHashingFailed(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            Self::DatabaseOperationFailed(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            Self::InvalidCredentials => (StatusCode::UNAUTHORIZED, self.to_string()),
            Self::JwtOperationFailed(_) => (StatusCode::UNAUTHORIZED, self.to_string()),
            Self::UserNotFound => (StatusCode::UNAUTHORIZED, self.to_string()),
            Self::TokenInvalid => (StatusCode::UNAUTHORIZED, self.to_string()),
            Self::OAuthOperationFailed(e) => (StatusCode::UNAUTHORIZED, e.to_string()),
        };

        let body = Json(json!({
            "result": "error",
            "message": error_message
        }));

        (status, body).into_response()
    }
}

/// Login route
pub async fn login(
    State(context): State<core::ArcContext>,
    Json(login): Json<Login>,
) -> Result<impl IntoResponse, AuthError> {
    tracing::info!("Logging in user: {}", login.username);

    // Get user from database
    let user = db::get_user_by_name(&context.db, &login.username).await?;
    if !auth::verify_password(&login.password, user.password_hash)? {
        tracing::warn!("Invalid password for user: {}", login.username);
        return Err(AuthError::InvalidCredentials);
    }

    // Generate JWT tokens with appropriate expiration
    let access_token = auth::generate_access_token(&context.jwt, user.id, &user.username, user.tenant_id)?;
    let refresh_token = auth::generate_refresh_token(&context.jwt, user.id)?;

    // store refresh token in database
    let refresh_claims = auth::decode_refresh_token(&context.jwt, &refresh_token)?;
    let expires_at = DateTime::from_timestamp(refresh_claims.exp, 0).ok_or(AuthError::TokenInvalid)?;
    let mut hasher = sha2::Sha256::new();
    hasher.update(&refresh_token);
    let token_hash = format!("{:x}", hasher.finalize());
    let new_refresh_token = db::NewRefreshToken {
        jti: refresh_claims.jti,
        user_id: user.id,
        token_hash: token_hash,
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
    tracing::info!(user_id = claims.sub, username = claims.username, "Logout");

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
    Json(request): Json<RefreshTokenRequest>,
) -> Result<impl IntoResponse, AuthError> {
    tracing::info!("Refreshing access token");

    // Decode refresh token and check if it exists in database and is not revoked
    let refresh_claims = auth::decode_refresh_token(&context.jwt, &request.refresh_token)?;
    let stored_token = db::get_refresh_token_by_jti(&context.db, &refresh_claims.jti).await?;

    // Verify token hash
    let mut hasher = sha2::Sha256::new();
    hasher.update(&request.refresh_token);
    let token_hash = format!("{:x}", hasher.finalize());
    if stored_token.token_hash != token_hash {
        return Err(AuthError::TokenInvalid);
    }

    // Generate new access token for the user
    let user = db::get_user_by_id(&context.db, stored_token.user_id).await?;
    let new_access_token = auth::generate_access_token(&context.jwt, user.id, &user.username, user.tenant_id)?;

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
pub async fn revoke_token(
    State(context): State<core::ArcContext>,
    Json(request): Json<RevokeTokenRequest>,
) -> Result<impl IntoResponse, AuthError> {
    tracing::info!("Revoking refresh token");

    // Decode refresh token to get JTI
    let refresh_claims = auth::decode_refresh_token(&context.jwt, &request.refresh_token)?;

    // Revoke the token
    db::revoke_refresh_token(&context.db, &refresh_claims.jti).await?;
    Ok(Json(json!({"result": "ok"})))
}

/// Handler for initiating Google OAuth flow
pub async fn google_auth_init(
    State(context): State<core::ArcContext>,
) -> Result<impl IntoResponse, AuthError> {
    let (auth_url, _csrf_token) = auth::get_google_auth_url(&context.config.oauth)?;
    // In production, you should store the CSRF token in a secure session store
    // For now, we'll rely on the OAuth provider's state validation
    Ok(axum::response::Redirect::to(auth_url.as_str()))
}

/// Handler for Google OAuth callback
pub async fn google_auth_callback(
    State(context): State<core::ArcContext>,
    axum::extract::Query(params): axum::extract::Query<auth::AuthRequest>,
) -> Result<impl IntoResponse, AuthError> {
    tracing::info!("Google OAuth callback received with state: {}", params.state);
    let user_info = auth::get_google_user_info(&context, &params.code).await?;
    tracing::info!("Retrieved user info for: {} ({})", user_info.name, user_info.email);

    // Check if user already exists
    let existing_user = db::get_user_by_sso_id(&context.db, "google", &user_info.id).await;
    let user = match existing_user {
        Ok(user) => {
            tracing::info!("Existing SSO user found: {}", user.username);
            user
        }
        Err(core::DbError::RowNotFound(_)) => {
            tracing::info!("No existing user found, creating new user for: {}", user_info.email);
            let new_user = db::NewUser {
                username: user_info.email.clone(), // Use email as username for SSO users
                password_hash: None,               // No password for SSO users
                email: Some(user_info.email.clone()),
                tenant_id: None, // You might want to assign a default tenant
                sso_provider: Some("google".to_string()),
                sso_id: Some(user_info.id.clone()),
            };
            let user = db::create_user(&context.db, new_user).await?;
            tracing::info!("Created new SSO user: {}", user.username);
            user
        }
        Err(e) => {
            tracing::error!("Failed to retrieve or create user: {}", e);
            return Err(AuthError::DatabaseOperationFailed(e));
        }
    };

    // TODO: move duplicate code (login function) to a common function
    // Generate JWT tokens for the user (same as regular login)
    let access_token = auth::generate_access_token(&context.jwt, user.id, &user.username, user.tenant_id)?;

    let refresh_token = auth::generate_refresh_token(&context.jwt, user.id)?;

    // Store refresh token in database
    let refresh_claims = auth::decode_refresh_token(&context.jwt, &refresh_token)?;
    let expires_at = chrono::DateTime::from_timestamp(refresh_claims.exp, 0).ok_or(auth::JwtError::InvalidToken)?;
    let mut hasher = sha2::Sha256::new();
    hasher.update(&refresh_token);
    let token_hash = format!("{:x}", hasher.finalize());
    let new_refresh_token = db::NewRefreshToken {
        jti: refresh_claims.jti,
        user_id: user.id,
        token_hash: token_hash,
        expires_at: expires_at.naive_utc(),
    };
    db::create_refresh_token(&context.db, new_refresh_token).await?;

    let jwt_token_response = auth::TokenResponse::new(&context.jwt, access_token, refresh_token);

    // For OAuth flow, redirect to frontend with success status
    // TODO: In production, consider a more secure approach like server-side session or secure cookies
    let redirect_url = format!(
        "http://localhost:5173/login?oauth_success=true&access_token={}&refresh_token={}",
        jwt_token_response.access_token, jwt_token_response.refresh_token
    );

    Ok(axum::response::Redirect::to(&redirect_url))
}
