use axum::Json;
use axum::body::Body;
use axum::extract::Request;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::response::Response;
use serde::Deserialize;
use serde_json::json;
use thiserror::Error;

use crate::auth;
use crate::core;
use crate::db;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Database operation failed: {0}")]
    DatabaseOperationFailed(core::DbError),

    #[error("JWT operation failed: {0}")]
    JwtOperationFailed(#[from] auth::JwtError),

    #[error("Password hashing failed: {0}")]
    PasswordHashingFailed(#[from] argon2::password_hash::Error),

    #[error("Token expired or invalid")]
    InvalidToken(#[from] auth::TokenError),

    #[error("User already exists")]
    UserAlreadyExists,

    #[error("SSO operation failed: {0}")]
    SsoOperationFailed(#[from] auth::SsoError),
}

impl From<core::DbError> for AuthError {
    fn from(db_error: core::DbError) -> Self {
        match db_error {
            core::DbError::RowNotFound => Self::InvalidCredentials,
            other => Self::DatabaseOperationFailed(other),
        }
    }
}

#[derive(Deserialize)]
pub struct Login {
    pub username: String, // TODO: replace with email
    pub password: String,
}

impl IntoResponse for AuthError {
    #[allow(clippy::match_same_arms)]
    fn into_response(self) -> Response {
        auth::log_auth_error(&self);
        let status = match self {
            Self::PasswordHashingFailed(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::DatabaseOperationFailed(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::InvalidCredentials => StatusCode::UNAUTHORIZED,
            Self::JwtOperationFailed(_) => StatusCode::UNAUTHORIZED,
            Self::InvalidToken(_) => StatusCode::UNAUTHORIZED,
            Self::SsoOperationFailed(_) => StatusCode::UNAUTHORIZED,
            Self::UserAlreadyExists => StatusCode::UNAUTHORIZED,
        };
        let body = Json(json!({
            "result": "error",
            "message": self.to_string(),
        }));
        (status, body).into_response()
    }
}

/// Handler for logging in using username and password credentials
pub async fn login(
    State(context): State<core::ArcContext>,
    headers: HeaderMap,
    Json(login): Json<Login>,
) -> Result<impl IntoResponse, AuthError> {
    auth::log_user_login(&headers, &login.username);
    let user = db::get_user_by_name(&context.db, &login.username).await?;
    let password_hash = user.password_hash.as_ref().ok_or_else(|| {
        auth::log_missing_password(&headers, &login.username);
        AuthError::InvalidCredentials
    })?;
    if !auth::verify_password(&login.password, &password_hash)? {
        auth::log_invalid_password(&headers, &login.username);
        return Err(AuthError::InvalidCredentials);
    }
    auth::log_user_login_success(&headers, &user.username);

    // generate JWT tokens with appropriate expiration
    let access_token = auth::generate_access_token(&context.jwt, user.id, &user.username, user.tenant_id)?;
    let refresh_token_with_claims = auth::generate_refresh_token(&context.jwt, user.id)?;

    // store refresh token in database
    let token_hash = auth::get_token_hash_as_hex(&refresh_token_with_claims.token);
    let new_refresh_token = db::NewRefreshToken {
        jti: refresh_token_with_claims.claims.jti,
        user_id: user.id,
        token_hash,
        expires_at: auth::get_token_expiration_as_naive_utc(refresh_token_with_claims.claims.exp)?,
    };
    db::create_refresh_token(&context.db, new_refresh_token).await?;

    let body = json!({
        "result": "ok",
        "user": {
            "id": user.id,
            "username": user.username,
            "tenant_id": user.tenant_id
        }
    });
    let refresh_token = refresh_token_with_claims.token;
    let r = auth::create_json_response_with_auth_cookies(&context, &Some(&access_token), &Some(&refresh_token), body)?;
    Ok(r)
}

/// Handler for logging out
pub async fn logout(
    State(context): State<core::ArcContext>,
    req: Request<Body>,
) -> Result<impl IntoResponse, AuthError> {
    // TODO: clarify what to do here in case of various errors.
    let claims = auth::decode_access_token_from_req(&context, &req)?;
    auth::log_user_logout(req.headers(), &claims.sub, &claims.username);

    // revoke all the associated refresh tokens
    let user_id = claims
        .sub
        .parse::<i64>()
        .map_err(|_| AuthError::InvalidToken(auth::TokenError::TokenInvalid))?;
    if let Ok(db_user) = db::get_user_by_id(&context.db, user_id).await {
        let _ = db::revoke_all_refresh_tokens_for_user(&context.db, db_user.id).await;
    }

    // create cookies to clear the tokens
    let json = json!({"result": "ok"});
    let r = auth::create_json_response_with_auth_cookies(&context, &None, &None, json)?;
    Ok(r)
}

/// Handler for refreshing access token using refresh token
pub async fn refresh_access_token(
    State(context): State<core::ArcContext>,
    req: Request<Body>,
) -> Result<impl IntoResponse, AuthError> {
    // attempt to extract refresh_token from the Cookie header
    let refresh_token = auth::get_refresh_token_from_cookie(&req)?;
    // decode refresh token and check if it exists in database and is not revoked
    let refresh_claims = auth::decode_refresh_token(&context.jwt, refresh_token)?;
    let stored_token = db::get_refresh_token_by_jti(&context.db, &refresh_claims.jti).await?;
    let token_hash = auth::get_token_hash_as_hex(refresh_token); // verify token hash
    if stored_token.token_hash != token_hash {
        return Err(AuthError::InvalidToken(auth::TokenError::TokenInvalid));
    }

    // generate new access token for the user
    let user = db::get_user_by_id(&context.db, stored_token.user_id).await?;
    let new_access_token = auth::generate_access_token(&context.jwt, user.id, &user.username, user.tenant_id)?;
    auth::log_token_refresh(req.headers(), user.id, &refresh_claims.jti, &refresh_claims.sub);

    let body = json!({
        "result": "ok",
        "expires_in": context.settings.jwt.access_token_expiry_minutes * 60,
        "user": {
            "id": user.id,
            "username": user.username,
            "tenant_id": user.tenant_id
        }
    });
    let r = auth::create_json_response_with_auth_cookies(&context, &Some(&new_access_token), &None, body)?;
    Ok(r)
}

/// Handler for revoking a refresh token
pub async fn revoke_refresh_token(
    State(context): State<core::ArcContext>,
    req: Request<Body>,
) -> Result<impl IntoResponse, AuthError> {
    // attempt to extract refresh_token from the Cookie header
    let refresh_token = auth::get_refresh_token_from_cookie(&req)?;
    // decode refresh token to get JTI
    let refresh_claims = auth::decode_refresh_token(&context.jwt, &refresh_token)?;
    db::revoke_refresh_token(&context.db, &refresh_claims.jti).await?; // revoke the token
    auth::log_token_revoke(req.headers(), &refresh_claims.jti, &refresh_claims.sub);

    let body = json!({"result": "ok"});
    let r = auth::create_json_response_with_auth_cookies(&context, &None, &None, body)?;
    Ok(r)
}

/// Handler for initiating Google OAuth flow
pub async fn google_auth_init(
    State(context): State<core::ArcContext>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<impl IntoResponse, AuthError> {
    let redirect_url = params.get("redirect_url");
    auth::log_oauth_flow_initiated("google", &headers, &redirect_url);
    let (auth_url, state) = auth::get_google_auth_url(&context, redirect_url).await?;
    auth::log_oauth_redirecting("google", &headers, &auth_url, &state);
    Ok(axum::response::Redirect::to(auth_url.as_str()))
}

/// Handler for Google OAuth callback
pub async fn google_auth_callback(
    State(context): State<core::ArcContext>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<auth::AuthRequest>,
) -> Result<impl IntoResponse, AuthError> {
    let (user_info, redirect_url) = auth::get_google_user_info(&context, &params.code, &params.state).await?;
    auth::log_oauth_callback_received("google", &headers, &params.state, &user_info.email);

    if !user_info.verified_email {
        auth::log_oauth_security_violation("unverified_email", &headers, &user_info.email, &params.state);
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

    auth::log_oauth_user_authenticated("google", &headers, &user_info.email, &params.state);

    // generate JWT tokens for the user (same as regular login)
    let access_token = auth::generate_access_token(&context.jwt, user.id, &user.username, user.tenant_id)?;
    let refresh_token_with_claims = auth::generate_refresh_token(&context.jwt, user.id)?;

    // store refresh token in database
    let new_refresh_token = db::NewRefreshToken {
        jti: refresh_token_with_claims.claims.jti,
        user_id: user.id,
        token_hash: auth::get_token_hash_as_hex(&refresh_token_with_claims.token),
        expires_at: auth::get_token_expiration_as_naive_utc(refresh_token_with_claims.claims.exp)?,
    };
    db::create_refresh_token(&context.db, new_refresh_token).await?;

    let final_redirect_url = redirect_url.as_deref().unwrap_or("/");
    let response = axum::response::Redirect::to(final_redirect_url).into_response();
    let response = auth::add_auth_cookies(
        &context,
        &Some(&access_token),
        &Some(&refresh_token_with_claims.token),
        response,
    )?;
    Ok(response)
}

pub async fn create_sso_user(
    context: &core::ArcContext,
    user_info: &auth::GoogleUserInfo,
    provider: &str,
    headers: &HeaderMap,
    state: &str,
) -> Result<db::User, AuthError> {
    auth::log_oauth_create_new_user(provider, headers, &user_info.email, state);

    // check if email is already in use by a non-SSO user
    if let Ok(_existing_user) = db::get_user_by_email(&context.db, &user_info.email).await {
        auth::log_oauth_security_violation("email_already_exists", headers, &user_info.email, state);
        return Err(AuthError::UserAlreadyExists);
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
