use axum::Json;
use axum::Router;
use axum::body::Body;
use axum::extract::Request;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use reqwest::StatusCode;
use serde::Deserialize;
use serde::Serialize;

use crate::api;
use crate::common;
use crate::identity::auth;
use crate::identity::tokens;
use crate::identity::users;
use crate::internal::logger;

pub fn router<UR, TR>(context: common::ArcContext, service: auth::Service<UR, TR>) -> Router<common::ArcContext>
where
    UR: users::TRepository + Clone + 'static,
    TR: tokens::TRepository + Clone + 'static,
{
    use axum::routing::post;
    Router::new()
        .route("/auth/login", post(login::<UR, TR>))
        .route("/auth/logout", post(logout::<UR, TR>))
        .route("/auth/refresh", post(refresh::<UR, TR>))
        .with_state(AppState { context, service })
}

#[derive(Clone)]
struct AppState<UR, TR>
where
    UR: users::TRepository + Clone + 'static,
    TR: tokens::TRepository + Clone + 'static,
{
    pub context: common::ArcContext,
    pub service: auth::Service<UR, TR>,
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

async fn login<UR, TR>(
    State(AppState { context, service }): State<AppState<UR, TR>>,
    headers: HeaderMap,
    Json(request): Json<LoginRequest>,
) -> Result<impl IntoResponse, api::Error>
where
    UR: users::TRepository + Clone,
    TR: tokens::TRepository + Clone,
{
    logger::log_user_login_attempt(&headers, &request.email);

    let email = common::Email::parse(&request.email).ok_or_else(api::Error::invalid_credentials)?;
    let cmd = auth::LoginCommand {
        email: email.clone(),
        password: request.password,
    };
    let session = service.login(&context, cmd).await?;

    logger::log_user_login_success(&headers, session.user.email.as_str());

    let body = LoginResponse {
        user: session.user.into(),
    };
    Ok(tokens::utils::create_response_with_auth_cookies(
        &context,
        &body,
        Some(&session.access_token.value),
        Some(&session.refresh_token.value),
    )?)
}

async fn logout<UR, TR>(
    State(AppState { context, service }): State<AppState<UR, TR>>,
    req: Request<Body>,
) -> Result<impl IntoResponse, api::Error>
where
    UR: users::TRepository + Clone,
    TR: tokens::TRepository + Clone,
{
    if let Ok(refresh_token) = tokens::utils::get_refresh_token_from_cookie(&req) {
        let _ = service.revoke_refresh_token(&context, refresh_token).await;
    }

    let response = axum::http::Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Body::empty())?;
    Ok(tokens::utils::add_auth_cookies(&context, response, None, None)?)
}

async fn refresh<UR, TR>(
    State(AppState { context, service }): State<AppState<UR, TR>>,
    req: Request<Body>,
) -> Result<impl IntoResponse, api::Error>
where
    UR: users::TRepository + Clone,
    TR: tokens::TRepository + Clone,
{
    let refresh_token = tokens::utils::get_refresh_token_from_cookie(&req)?;
    let session = service.refresh(&context, refresh_token).await?;

    logger::log_token_refresh(
        req.headers(),
        session.user.id.0,
        session.old_jti.as_deref().unwrap_or(""),
        &session.user.id.0.to_string(),
    );

    let body = RefreshResponse {
        expires_in: context.jwt.access_token_expiry,
        user: session.user.into(),
    };
    Ok(tokens::utils::create_response_with_auth_cookies(
        &context,
        &body,
        Some(&session.access_token.value),
        Some(&session.refresh_token.value),
    )?)
}
