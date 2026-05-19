use axum::Json;
use axum::body::Body;
use axum::extract::Request;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use serde::Deserialize;
use serde::Serialize;
use serde_json::json;

use crate::auth::{self, AuthError};
use crate::common;
use crate::db;

/// Default tenant ID assigned to users created via SSO.
const SSO_DEFAULT_TENANT_ID: i64 = 0;

#[derive(Deserialize)]
pub struct Login {
    pub email: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct User {
    pub id: i64,
    pub email: String,
    pub tenant_id: i64,
}

impl From<&db::User> for User {
    fn from(u: &db::User) -> Self {
        Self {
            id: u.id,
            email: u.email.clone(),
            tenant_id: u.tenant_id,
        }
    }
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub user: User,
}

#[derive(Serialize)]
pub struct RefreshResponse {
    pub expires_in: u32,
    pub user: User,
}

#[derive(Serialize)]
pub struct UserInfoResponse {
    pub user: User,
}

fn is_temporarily_locked(user: &db::User) -> bool {
    if user.failed_login_count < common::constants::auth::FAILED_LOGIN_MAX_ATTEMPTS {
        return false;
    }
    user.last_failed_login.is_some_and(|last| {
        chrono::Utc::now().naive_utc() - last
            < chrono::Duration::minutes(common::constants::auth::FAILED_LOGIN_WINDOW_MINUTES)
    })
}

// Login handler - verifies user credentials and creates a response with access and refresh tokens set in HttpOnly cookies
pub async fn login(
    State(context): State<common::ArcContext>,
    headers: HeaderMap,
    Json(login): Json<Login>,
) -> Result<impl IntoResponse, AuthError> {
    auth::log_user_login_attempt(&headers, &login.email);
    let email_normalized = common::normalize_email(&login.email);

    let maybe_user = db::get_user_by_email(&context.db, &email_normalized).await.ok();

    // check account lockout before doing any password work
    if let Some(user) = &maybe_user
        && is_temporarily_locked(user)
    {
        // TODO: should we log this?
        // should we return another error, to make it clear that the account is temporarily locked?
        return Err(AuthError::InvalidCredentials);
    }

    if matches!(&maybe_user, Some(u) if u.password_hash.is_none()) {
        auth::log_missing_password(&headers, &email_normalized);
    }

    let password_hash = maybe_user
        .as_ref()
        .and_then(|u| u.password_hash.as_deref())
        .ok_or_else(|| {
            let _ = auth::verify_password(&login.password, auth::DUMMY_HASH);
            AuthError::InvalidCredentials
        })?;

    if !auth::verify_password(&login.password, password_hash)? {
        auth::log_invalid_password(&headers, &email_normalized);
        if let Some(user) = &maybe_user {
            db::increment_failed_login(&context.db, user.id).await?;
        }
        return Err(AuthError::InvalidCredentials);
    }

    let user = maybe_user.ok_or(AuthError::InvalidCredentials)?;
    db::reset_failed_login(&context.db, user.id).await?;
    auth::log_user_login_success(&headers, &email_normalized);

    let access_token = generate_access_token(&context, &user)?;
    let refresh_token = generate_refresh_token(&context, &user)?;

    let token_hash = auth::get_token_hash_as_hex(&refresh_token.value);
    let new_refresh_token = db::NewRefreshToken {
        jti: refresh_token.claims.jti,
        tenant_id: user.tenant_id,
        user_id: user.id,
        token_hash,
        expires_at: auth::get_token_expiration_as_naive_utc(refresh_token.claims.exp)?,
    };
    db::create_refresh_token(&context.db, new_refresh_token).await?;

    let body = LoginResponse { user: (&user).into() };
    let r = auth::create_response_with_auth_cookies(
        &context,
        &body,
        Some(&access_token.value),
        Some(&refresh_token.value),
    )?;
    Ok(r)
}

/// Logout handler - revokes the refresh token and clears cookies
pub async fn logout(
    State(context): State<common::ArcContext>,
    req: Request<Body>,
) -> Result<impl IntoResponse, AuthError> {
    try_revoke_refresh_token(&context, req).await?;
    let body = json!({});
    let r = auth::create_response_with_auth_cookies(&context, &body, None, None)?;
    Ok(r)
}

/// Refresh handler - generates new tokens using a valid refresh token
pub async fn refresh(
    State(context): State<common::ArcContext>,
    req: Request<Body>,
) -> Result<impl IntoResponse, AuthError> {
    // attempt to extract and decode the refresh_token from the Cookie header
    let refresh_token = auth::get_refresh_token_from_cookie(&req)?;
    let claims = auth::decode_token(&context.jwt, refresh_token, auth::TokenType::Refresh)?;

    // get the refresh tokens from db, including revoked ones to detect reuse
    // for example, if a token was stolen and used by an attacker:
    // the attacker uses valid refresh_token_v1 -> gets refresh_token_v2 and revokes refresh_token_v1 in DB
    // the valid user tries to use the same refresh_token_v1 -> we detect that it was already revoked
    // this is treated it as a potential reuse attack, and we revoke all refresh tokens for that user as a precaution
    let stored_token = db::get_refresh_token_by_jti(&context.db, claims.tenant_id, &claims.jti).await?;
    if stored_token.revoked_at.is_some() {
        let _ = db::revoke_all_refresh_tokens_for_user(&context.db, claims.tenant_id, stored_token.user_id).await;
        return Err(AuthError::InvalidToken(auth::TokenError::TokenInvalid));
    }

    // verify token hash
    let token_hash = auth::get_token_hash_as_hex(refresh_token);
    if stored_token.token_hash != token_hash {
        return Err(AuthError::InvalidToken(auth::TokenError::TokenInvalid));
    }

    // revoke old refresh token
    db::revoke_refresh_token(&context.db, &claims.jti).await?;

    // generate and store a new refresh token for the user
    let user = db::get_user_by_id(&context.db, stored_token.user_id).await?;
    let new_refresh_token_data = generate_refresh_token(&context, &user)?;
    let new_token_hash = auth::get_token_hash_as_hex(&new_refresh_token_data.value);
    let new_refresh_token_db = db::NewRefreshToken {
        jti: new_refresh_token_data.claims.jti.clone(),
        tenant_id: user.tenant_id,
        user_id: user.id,
        token_hash: new_token_hash,
        expires_at: auth::get_token_expiration_as_naive_utc(new_refresh_token_data.claims.exp)?,
    };
    db::create_refresh_token(&context.db, new_refresh_token_db).await?;
    auth::log_token_refresh(req.headers(), user.id, &claims.jti, &claims.sub);

    let body = RefreshResponse {
        expires_in: context.settings.jwt.access_token_expiry_minutes * 60,
        user: (&user).into(),
    };
    // set both new access token and new refresh token in cookies
    let new_access_token = generate_access_token(&context, &user)?;
    let r = auth::create_response_with_auth_cookies(
        &context,
        &body,
        Some(&new_access_token.value),
        Some(&new_refresh_token_data.value),
    )?;
    Ok(r)
}

/// User info handler - returns user information based on the access token
pub async fn user_info(
    State(context): State<common::ArcContext>,
    req: Request<Body>,
) -> Result<Json<UserInfoResponse>, AuthError> {
    let claims = auth::decode_token_from_req(&context, &req, auth::TokenType::Access)?;
    let user_id = claims
        .sub
        .parse::<i64>()
        .map_err(|_| AuthError::InvalidToken(auth::TokenError::TokenInvalid))?;
    let user = db::get_user_by_id(&context.db, user_id).await?;
    Ok(Json(UserInfoResponse { user: (&user).into() }))
}

/// Google OAuth initiation handler - redirects user to Google's OAuth consent screen
pub async fn google_auth_init(
    State(context): State<common::ArcContext>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<std::collections::BTreeMap<String, String>>,
) -> Result<impl IntoResponse, AuthError> {
    let redirect_url = params.get("redirect_url").cloned();
    auth::log_oauth_flow_initiated(&headers, &redirect_url, "google");

    let (auth_url, state_jwt) = auth::get_google_auth_url_and_csrf_token(&context, redirect_url)?;
    auth::log_oauth_redirecting(&headers, &auth_url, "google");

    let mut response = axum::response::Redirect::to(auth_url.as_str()).into_response();

    let cookie_max_age = context.settings.oauth.session_timeout_minutes * 60;
    let cookie = format!(
        "oauth_state={state_jwt}; HttpOnly; Secure; SameSite=Lax; Path=/api/oauth/google/callback; Max-Age={cookie_max_age}"
    );
    let cookie_val = axum::http::HeaderValue::from_str(&cookie)?;

    response
        .headers_mut()
        .insert(axum::http::header::SET_COOKIE, cookie_val);

    Ok(response)
}

/// Google OAuth callback handler - processes the OAuth callback and logs the user in
pub async fn google_auth_callback(
    State(context): State<common::ArcContext>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<auth::AuthRequest>,
) -> Result<impl IntoResponse, AuthError> {
    let oauth_state_cookie = auth::get_cookie_value_from_headers(&headers, "oauth_state").ok_or_else(|| {
        auth::log_cookie_error(&headers, "missing_oauth_state");
        AuthError::SsoOperationFailed(auth::SsoError::CsrfValidationFailed)
    })?;

    let (user_info, redirect_url) =
        auth::get_google_user_info(&context, &headers, &params.code, &params.state, oauth_state_cookie).await?;

    if !user_info.verified_email {
        auth::log_oauth_security_violation(&headers, &params.state, &user_info.email, "unverified_email", "google");
        return Err(AuthError::InvalidCredentials);
    }

    auth::log_oauth_user_authenticated(&headers, &params.state, &user_info.email, "google");

    // insert new user or link existing user if user already exists (matching email)
    let email_normalized = common::normalize_email(&user_info.email);
    let user = db::create_or_link_sso_user(
        &context.db,
        &email_normalized,
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
    let clear_cookie = "oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/api/oauth/google/callback; Max-Age=0";
    let cookie_val = axum::http::HeaderValue::from_static(clear_cookie);
    response
        .headers_mut()
        .append(axum::http::header::SET_COOKIE, cookie_val);

    // store refresh token in database if everthing went fine
    let new_refresh_token = db::NewRefreshToken {
        jti: refresh_token.claims.jti,
        tenant_id: user.tenant_id,
        user_id: user.id,
        token_hash: auth::get_token_hash_as_hex(&refresh_token.value),
        expires_at: auth::get_token_expiration_as_naive_utc(refresh_token.claims.exp)?,
    };
    db::create_refresh_token(&context.db, new_refresh_token).await?;

    Ok(response)
}

fn generate_refresh_token(context: &common::ArcContext, user: &db::User) -> Result<auth::TokenWithClaims, AuthError> {
    Ok(auth::generate_token(
        &context.jwt,
        user.id,
        user.tenant_id,
        &user.email,
        auth::TokenType::Refresh,
        context.jwt.refresh_token_expiry,
    )?)
}

fn generate_access_token(context: &common::ArcContext, user: &db::User) -> Result<auth::TokenWithClaims, AuthError> {
    Ok(auth::generate_token(
        &context.jwt,
        user.id,
        user.tenant_id,
        &user.email,
        auth::TokenType::Access,
        context.jwt.access_token_expiry,
    )?)
}

async fn try_revoke_refresh_token(context: &common::ArcContext, req: Request<Body>) -> Result<(), AuthError> {
    // extract cookie - if missing, they are technically already logged out
    let Ok(refresh_token) = auth::get_refresh_token_from_cookie(&req) else {
        return Ok(());
    };

    // decode token - if it's expired or invalid, we don't need to revoke it in the DB.
    let Ok(claims) = auth::decode_token(&context.jwt, refresh_token, auth::TokenType::Refresh) else {
        return Ok(());
    };

    // database revocation - if this fails, we want the ? to trigger a 500 error
    db::revoke_refresh_token(&context.db, &claims.jti).await?;

    auth::log_user_logout(req.headers(), &claims.sub, &claims.email);

    Ok(())
}
