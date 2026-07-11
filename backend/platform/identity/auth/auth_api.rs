use axum;
use axum::extract::State;
use axum::http;
use axum::response::IntoResponse;
use serde::Deserialize;
use serde::Serialize;
use tracing::info;
use utoipax;

use crate::platform::api;
use crate::platform::common;
use crate::platform::cookies;
use crate::platform::crypto;

use crate::platform::identity::auth;
use crate::platform::identity::users;

#[cfg(debug_assertions)]
const MIN_PASSWORD_CHARS: u64 = 1;
#[cfg(not(debug_assertions))]
const MIN_PASSWORD_CHARS: u64 = 8;

pub fn router(service: auth::Service) -> utoipax::router::OpenApiRouter<common::ArcContext> {
    use utoipax::routes;

    let login_register_router = utoipax::router::OpenApiRouter::new()
        .routes(routes!(register))
        .routes(routes!(login));

    let logout_refresh_router = utoipax::router::OpenApiRouter::new()
        .routes(routes!(logout))
        .routes(routes!(refresh));

    let login_register_router = crate::platform::rate_limiter::add_login_rate_limiting(
        login_register_router,
        &service.context.settings.rate_limiter.login,
    );

    login_register_router.merge(logout_refresh_router).with_state(service)
}

#[derive(Deserialize, validator::Validate, utoipa::ToSchema)]
pub struct RegisterRequest {
    #[validate(
        email(message = "invalid email address"),
        length(max = 254, message = "email address must be 254 characters or less")
    )]
    #[schema(example = "alice@example.com", format = "email", max_length = 254)]
    pub email: String,

    #[validate(length(min = MIN_PASSWORD_CHARS, max = 1024, message = "password must be between 8 and 1024 characters"))]
    #[schema(min_length = 8, max_length = 1024)]
    pub password: String,

    #[validate(length(max = 100, message = "first name must be 100 characters or less"))]
    #[schema(max_length = 100)]
    pub first_name: Option<String>,

    #[validate(length(max = 100, message = "last name must be 100 characters or less"))]
    #[schema(max_length = 100)]
    pub last_name: Option<String>,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct RegisterResponse {
    pub user: users::api::UserInfo,
}

#[derive(Deserialize, validator::Validate, utoipa::ToSchema)]
pub struct LoginRequest {
    #[validate(
        email(message = "invalid email address"),
        length(max = 254, message = "email address must be 254 characters or less")
    )]
    #[schema(example = "alice@example.com", format = "email", max_length = 254)]
    pub email: String,

    #[validate(length(min = MIN_PASSWORD_CHARS, max = 1024, message = "password must be between 8 and 1024 characters"))]
    #[schema(min_length = 8, max_length = 1024)]
    pub password: String,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct LoginResponse {
    pub expires_in: u32,
    pub user: users::api::UserInfo,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct RefreshResponse {
    pub expires_in: u32,
    pub user: users::api::UserInfo,
}

#[utoipa::path(
    post,
    path = "/auth/register",
    request_body = RegisterRequest,
    responses(
        (status = 201, description = "Registration successful", body = RegisterResponse),
        (status = 400, description = "Validation failed", body = api::Error),
        (status = 409, description = "User already exists", body = api::Error)
    )
)]
async fn register(
    State(service): State<auth::Service>,
    request: api::ValidatedJson<RegisterRequest>,
) -> Result<impl IntoResponse, api::Error> {
    let request = request.data();
    let email = common::Email::parse(&request.email)
        .ok_or_else(|| api::Error::validation_failed("email", "invalid email format"))?;
    let user = service
        .register(email, request.password, request.first_name, request.last_name)
        .await?;
    let body = RegisterResponse { user: user.into() };
    Ok((http::StatusCode::CREATED, axum::Json(body)))
}

#[utoipa::path(
    post,
    path = "/auth/login",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login successful", body = LoginResponse),
        (status = 400, description = "Validation failed", body = api::Error),
        (status = 401, description = "Invalid credentials", body = api::Error)
    )
)]
async fn login(
    State(service): State<auth::Service>,
    request: api::ValidatedJson<LoginRequest>,
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

#[utoipa::path(
    post,
    path = "/auth/logout",
    responses(
        (status = 204, description = "Logout successful"),
        (status = 401, description = "Unauthorized", body = api::Error),
        (status = 500, description = "Internal Server Error", body = api::Error)
    )
)]
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
    let response = cookies::add_auth_cookies(&service.context.settings.jwt, response, None, None)?;
    Ok(response)
}

#[utoipa::path(
    post,
    path = "/auth/refresh",
    responses(
        (status = 200, description = "Session refresh successful", body = RefreshResponse),
        (status = 401, description = "Unauthorized", body = api::Error)
    )
)]
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
