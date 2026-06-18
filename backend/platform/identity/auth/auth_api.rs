use axum;
use axum::extract::State;
use axum::http;
use axum::response::IntoResponse;
use serde::Deserialize;
use serde::Serialize;
use tracing::info;

use crate::platform::api;
use crate::platform::common;
use crate::platform::cookies;
use crate::platform::crypto;

use crate::platform::identity::auth;
use crate::platform::identity::users;

pub fn router(service: auth::Service) -> axum::Router<common::ArcContext> {
    use crate::platform::rate_limiter;
    use axum::routing::post;

    let base_router = axum::Router::new()
        .route("/auth/register", post(register))
        .route("/auth/login", post(login));

    // strict brute-force protection for unauthenticated, CPU-heavy routes (e.g. argon2 hashing on login).
    let rate_limited_router =
        rate_limiter::add_login_rate_limiting(base_router, &service.context.settings.rate_limiter.login);

    // logout and refresh are protected by the global rate limiter; they use cheap token validation
    // and would block legitimate background client refreshes if subjected to strict login limits.
    rate_limited_router
        .route("/auth/logout", post(logout))
        .route("/auth/refresh", post(refresh))
        .with_state(service)
}

#[derive(Deserialize, validator::Validate)]
pub struct RegisterRequest {
    #[validate(email(message = "invalid email address"))]
    pub email: String,
    #[validate(length(min = 8, message = "password must be at least 8 characters"))]
    pub password: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub user: UserResponse,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub user: UserResponse,
}

#[derive(Serialize)]
pub struct RefreshResponse {
    pub expires_in: u32,
    pub user: UserResponse,
}

#[derive(Serialize)]
pub struct UserResponse {
    pub id: i64,
    pub email: String,
    pub tenant_id: i64,
}

impl From<users::User> for UserResponse {
    fn from(user: users::User) -> Self {
        Self {
            id: user.id.0,
            email: user.email.as_str().to_string(),
            tenant_id: user.tenant_id.0,
        }
    }
}

async fn register(
    State(service): State<auth::Service>,
    request: api::ValidatedJson<RegisterRequest>,
) -> Result<impl IntoResponse, api::Error> {
    let request = request.data();
    let email = common::Email::parse(&request.email)
        .ok_or_else(|| api::Error::validation_failed("email", "invalid email format"))?;
    let user = service
        .register(email, &request.password, request.first_name, request.last_name)
        .await?;
    let body = RegisterResponse { user: user.into() };
    Ok((http::StatusCode::CREATED, axum::Json(body)))
}

async fn login(
    State(service): State<auth::Service>,
    request: api::Json<LoginRequest>,
) -> Result<impl IntoResponse, api::Error> {
    let request = request.data();
    let email_hash = crypto::get_hash_as_hex(&request.email);
    info!(%email_hash, "login_attempt");
    let email = common::Email::parse(&request.email).ok_or_else(api::Error::invalid_credentials)?;
    let cmd = auth::LoginCommand {
        email: email.clone(),
        password: request.password,
    };
    let session = service.login(cmd).await?;
    let success_email_hash = crypto::get_hash_as_hex(session.user.email.as_str());
    info!(
        user_id = session.user.id.0,
        email_hash = %success_email_hash,
        "login_success"
    );
    let body = LoginResponse {
        user: session.user.into(),
    };
    Ok(cookies::create_response_with_auth_cookies(
        &service.context.settings.jwt,
        &body,
        Some(&session.access_token.value),
        Some(&session.refresh_token.value),
    )?)
}

async fn logout(
    State(service): State<auth::Service>,
    headers: http::HeaderMap,
) -> Result<impl IntoResponse, api::Error> {
    if let Ok(refresh_token) = cookies::get_refresh_token_from_cookie(&headers) {
        let _ = service.revoke_refresh_token(&refresh_token).await;
    }
    let response = axum::http::Response::builder()
        .status(http::StatusCode::NO_CONTENT)
        .body(axum::body::Body::empty())?;
    Ok(cookies::add_auth_cookies(
        &service.context.settings.jwt,
        response,
        None,
        None,
    )?)
}

async fn refresh(
    State(service): State<auth::Service>,
    headers: http::HeaderMap,
) -> Result<impl IntoResponse, api::Error> {
    let refresh_token = cookies::get_refresh_token_from_cookie(&headers)?;
    let session = service.refresh(&refresh_token).await?;
    info!(
        user_id = session.user.id.0,
        jti = session.old_jti.as_deref().unwrap_or(""),
        "session_refresh"
    );
    let body = RefreshResponse {
        expires_in: service.context.jwt.access_token_expiry,
        user: session.user.into(),
    };
    Ok(cookies::create_response_with_auth_cookies(
        &service.context.settings.jwt,
        &body,
        Some(&session.access_token.value),
        Some(&session.refresh_token.value),
    )?)
}
