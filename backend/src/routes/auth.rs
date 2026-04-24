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

/// Default tenant ID assigned to users created via SSO.
const SSO_DEFAULT_TENANT_ID: i64 = 0;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Internal error: {0}")]
    RequestHeaderOperationFailed(#[from] axum::http::header::InvalidHeaderValue),

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
    pub email: String,
    pub password: String,
}

impl IntoResponse for AuthError {
    #[allow(clippy::match_same_arms)]
    fn into_response(self) -> Response {
        auth::log_auth_error(&self);
        let status = match self {
            Self::PasswordHashingFailed(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::DatabaseOperationFailed(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::RequestHeaderOperationFailed(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::InvalidCredentials => StatusCode::UNAUTHORIZED,
            Self::JwtOperationFailed(_) => StatusCode::UNAUTHORIZED,
            Self::InvalidToken(_) => StatusCode::UNAUTHORIZED,
            Self::SsoOperationFailed(_) => StatusCode::UNAUTHORIZED,
            Self::UserAlreadyExists => StatusCode::CONFLICT,
        };
        let body = Json(json!({
            "result": "error",
            "message": self.to_string(),
        }));
        (status, body).into_response()
    }
}

/// Handler for logging in using email and password credentials
pub async fn login(
    State(context): State<core::ArcContext>,
    headers: HeaderMap,
    Json(login): Json<Login>,
) -> Result<impl IntoResponse, AuthError> {
    auth::log_user_login(&headers, &login.email);
    let user = db::get_user_by_email(&context.db, &login.email).await?;
    let password_hash = user.password_hash.as_ref().ok_or_else(|| {
        auth::log_missing_password(&headers, &login.email);
        AuthError::InvalidCredentials
    })?;
    if !auth::verify_password(&login.password, password_hash)? {
        auth::log_invalid_password(&headers, &login.email);
        return Err(AuthError::InvalidCredentials);
    }
    auth::log_user_login_success(&headers, &user.email);

    // generate JWT tokens with appropriate expiration
    let access_token = generate_access_token(&context, &user)?;
    let refresh_token = generate_refresh_token(&context, &user)?;

    // store refresh token in database
    let token_hash = auth::get_token_hash_as_hex(&refresh_token.value);
    let new_refresh_token = db::NewRefreshToken {
        jti: refresh_token.claims.jti,
        user_id: user.id,
        token_hash,
        expires_at: auth::get_token_expiration_as_naive_utc(refresh_token.claims.exp)?,
    };
    db::create_refresh_token(&context.db, new_refresh_token).await?;

    let body = json!({
        "result": "ok",
        "user": {
            "id": user.id,
            "email": user.email,
            "tenant_id": user.tenant_id
        }
    });
    let r = auth::create_json_response_with_auth_cookies(
        &context,
        Some(&access_token.value),
        Some(&refresh_token.value),
        body,
    )?;
    Ok(r)
}

/// Handler for logging out
pub async fn logout(
    State(context): State<core::ArcContext>,
    req: Request<Body>,
) -> Result<impl IntoResponse, AuthError> {
    // TODO: clarify what to do here in case of various errors.
    let claims = auth::decode_token_from_req(&context, &req, auth::TokenType::Access)?;
    auth::log_user_logout(req.headers(), &claims.sub, &claims.email);

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
    let r = auth::create_json_response_with_auth_cookies(&context, None, None, json)?;
    Ok(r)
}

/// Handler for refreshing access token using refresh token
pub async fn refresh_access_token(
    State(context): State<core::ArcContext>,
    req: Request<Body>,
) -> Result<impl IntoResponse, AuthError> {
    // attempt to extract refresh_token from the Cookie header
    let refresh_token = auth::get_refresh_token_from_cookie(&req)?;
    // decode refresh token and check if it exists in the database and is not revoked
    let refresh_claims = auth::decode_token(&context.jwt, refresh_token, auth::TokenType::Refresh)?;
    let stored_token = db::get_refresh_token_by_jti(&context.db, &refresh_claims.jti).await?;
    let token_hash = auth::get_token_hash_as_hex(refresh_token); // verify token hash
    if stored_token.token_hash != token_hash {
        return Err(AuthError::InvalidToken(auth::TokenError::TokenInvalid));
    }

    // generate new access token for the user
    let user = db::get_user_by_id(&context.db, stored_token.user_id).await?;
    let new_access_token = generate_access_token(&context, &user)?;
    auth::log_token_refresh(req.headers(), user.id, &refresh_claims.jti, &refresh_claims.sub);

    let body = json!({
        "result": "ok",
        "expires_in": context.settings.jwt.access_token_expiry_minutes * 60,
        "user": {
            "id": user.id,
            "email": user.email,
            "tenant_id": user.tenant_id
        }
    });
    let r = auth::create_json_response_with_auth_cookies(&context, Some(&new_access_token.value), None, body)?;
    Ok(r)
}

/// Handler for checking session status
pub async fn session(
    State(context): State<core::ArcContext>,
    req: Request<Body>,
) -> Result<impl IntoResponse, AuthError> {
    match auth::decode_token_from_req(&context, &req, auth::TokenType::Access) {
        Ok(claims) => {
            let user_id = claims.sub.parse::<i64>().map_err(|_| AuthError::InvalidToken(auth::TokenError::TokenInvalid))?;
            let user = db::get_user_by_id(&context.db, user_id).await?;
            Ok(Json(json!({
                "result": "ok",
                "user": {
                    "id": user.id,
                    "email": user.email,
                    "tenant_id": user.tenant_id
                }
            })))
        }
        Err(_) => {
            Ok(Json(json!({
                "result": "error",
                "message": "Not authenticated"
            })))
        }
    }
}

/// Handler for revoking a refresh token
pub async fn revoke_refresh_token(
    State(context): State<core::ArcContext>,
    req: Request<Body>,
) -> Result<impl IntoResponse, AuthError> {
    // attempt to extract refresh_token from the Cookie header
    let refresh_token = auth::get_refresh_token_from_cookie(&req)?;
    // decode refresh token to get JTI
    let refresh_claims = auth::decode_token(&context.jwt, refresh_token, auth::TokenType::Refresh)?;
    db::revoke_refresh_token(&context.db, &refresh_claims.jti).await?;
    auth::log_token_revoke(req.headers(), &refresh_claims.jti, &refresh_claims.sub);

    let body = json!({"result": "ok"});
    let r = auth::create_json_response_with_auth_cookies(&context, None, None, body)?;
    Ok(r)
}

/// Handler for initiating Google OAuth flow
pub async fn google_auth_init(
    State(context): State<core::ArcContext>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<std::collections::BTreeMap<String, String>>,
) -> Result<impl IntoResponse, AuthError> {
    let redirect_url = params.get("redirect_url").cloned();
    auth::log_oauth_flow_initiated(&headers, &redirect_url, "google");

    let (auth_url, state_jwt) = auth::get_google_auth_url_and_csrf_token(&context, redirect_url)?;
    auth::log_oauth_redirecting(&headers, &auth_url, "google");

    let mut response = axum::response::Redirect::to(auth_url.as_str()).into_response();

    let cookie_max_age = context.settings.oauth.session_timeout_minutes * 60;
    let cookie = format!("oauth_state={state_jwt}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age={cookie_max_age}");
    let cookie_val = axum::http::HeaderValue::from_str(&cookie)?;

    response
        .headers_mut()
        .insert(axum::http::header::SET_COOKIE, cookie_val);

    Ok(response)
}

/// Handler for Google OAuth callback
pub async fn google_auth_callback(
    State(context): State<core::ArcContext>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<auth::AuthRequest>,
) -> Result<impl IntoResponse, AuthError> {
    let oauth_state_cookie = headers
        .get(axum::http::header::COOKIE)
        .ok_or(AuthError::SsoOperationFailed(auth::SsoError::CsrfValidationFailed))
        .and_then(|c| {
            c.to_str().map_err(|e| {
                auth::log_internal_error(&e, "cookie_utf8_decode");
                AuthError::SsoOperationFailed(auth::SsoError::CsrfValidationFailed)
            })
        })
        .and_then(|c| {
            c.split(';')
                .find_map(|p| {
                    let mut parts = p.trim().splitn(2, '=');
                    if parts.next()? == "oauth_state" {
                        parts.next()
                    } else {
                        None
                    }
                })
                .ok_or_else(|| {
                    auth::log_cookie_error(&headers, "missing_oauth_state");
                    AuthError::SsoOperationFailed(auth::SsoError::CsrfValidationFailed)
                })
        })?;

    let (user_info, redirect_url) =
        auth::get_google_user_info(&context, &params.code, &params.state, oauth_state_cookie).await?;

    if !user_info.verified_email {
        auth::log_oauth_security_violation(&headers, &params.state, &user_info.email, "unverified_email", "google");
        return Err(AuthError::InvalidCredentials);
    }

    auth::log_oauth_user_authenticated(&headers, &params.state, &user_info.email, "google");

    // insert new user or link existing user if user already exists (matching email)
    let user = db::create_or_link_sso_user(
        &context.db,
        &user_info.email,
        SSO_DEFAULT_TENANT_ID,
        "google",
        &user_info.id,
    )
    .await?;

    // generate JWT tokens for the user (same as regular login)
    let access_token = generate_access_token(&context, &user)?;
    let refresh_token = generate_refresh_token(&context, &user)?;

    // redirect back to the original URL or root
    // redirect_url was already validated and signed into the JWT at initiation time
    let final_redirect_url = redirect_url.as_deref().unwrap_or("/");

    let response = axum::response::Redirect::to(final_redirect_url).into_response();
    let mut response = auth::add_auth_cookies(
        &context,
        Some(&access_token.value),
        Some(&refresh_token.value),
        response,
    )?;

    // clear oauth_state cookie by setting Max-Age=0
    let clear_cookie = "oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0";
    let cookie_val = axum::http::HeaderValue::from_static(clear_cookie);
    response
        .headers_mut()
        .append(axum::http::header::SET_COOKIE, cookie_val);

    // store refresh token in database if everthing went fine
    let new_refresh_token = db::NewRefreshToken {
        jti: refresh_token.claims.jti,
        user_id: user.id,
        token_hash: auth::get_token_hash_as_hex(&refresh_token.value),
        expires_at: auth::get_token_expiration_as_naive_utc(refresh_token.claims.exp)?,
    };
    db::create_refresh_token(&context.db, new_refresh_token).await?;

    Ok(response)
}

fn generate_refresh_token(context: &core::ArcContext, user: &db::User) -> Result<auth::TokenWithClaims, AuthError> {
    Ok(auth::generate_token(
        &context.jwt,
        user.id,
        user.tenant_id,
        &user.email,
        auth::TokenType::Refresh,
        context.jwt.refresh_token_expiry,
    )?)
}

fn generate_access_token(context: &core::ArcContext, user: &db::User) -> Result<auth::TokenWithClaims, AuthError> {
    Ok(auth::generate_token(
        &context.jwt,
        user.id,
        user.tenant_id,
        &user.email,
        auth::TokenType::Access,
        context.jwt.access_token_expiry,
    )?)
}
