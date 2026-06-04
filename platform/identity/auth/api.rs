use axum::Json;
use axum::Router;
use axum::body::Body;
use axum::extract::Request;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::routing::post;
use reqwest::StatusCode;
use serde::Deserialize;
use serde::Serialize;

use super::service::{AuthError, AuthService, LoginCommand, RefreshTokenRepo};
use crate::common::ApiError;
use crate::common::ArcContext;
use crate::identity::users;
use crate::identity::users::service::UserRepo;
use crate::internal::logger;
use crate::internal::tokens;

#[derive(Clone)]
pub struct AuthState<UR: UserRepo, R: RefreshTokenRepo> {
    pub context: ArcContext,
    pub service: AuthService<UR, R>,
}

pub fn router<UR, R>(ctx: ArcContext, auth_service: AuthService<UR, R>) -> Router<ArcContext>
where
    UR: UserRepo + Clone + 'static,
    R: RefreshTokenRepo + Clone + 'static,
{
    let state = AuthState {
        context: ctx,
        service: auth_service,
    };
    Router::new()
        .route("/auth/login", post(login::<UR, R>))
        .route("/auth/logout", post(logout::<UR, R>))
        .route("/auth/refresh", post(refresh::<UR, R>))
        .with_state(state)
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

impl From<&crate::identity::users::service::User> for UserResponse {
    fn from(user: &crate::identity::users::service::User) -> Self {
        Self {
            id: user.id.0,
            email: user.email.as_str().to_string(),
            tenant_id: user.tenant_id.0,
        }
    }
}

impl From<AuthError> for ApiError {
    fn from(error: AuthError) -> Self {
        match error {
            AuthError::InvalidCredentials => Self::invalid_credentials(),
            AuthError::InvalidToken => Self::invalid_token(),
            AuthError::TokenOperationFailed(token_error) => token_error.into_api_error(),
            AuthError::JwtOperationFailed(jwt_error) => jwt_error.into_api_error(),
            AuthError::UserAlreadyExists => Self::user_already_exists(),
            // AuthError::UserOperationFailed(user_error) => user_error.into(),
            AuthError::PasswordHashingFailed(_) | AuthError::Database(_) | AuthError::Internal(_) => {
                tracing::error!("auth error: {error}");
                Self::internal()
            }
        }
    }
}

pub async fn login<UR, R>(
    State(state): State<AuthState<UR, R>>,
    headers: HeaderMap,
    Json(request): Json<LoginRequest>,
) -> Result<impl IntoResponse, ApiError>
where
    UR: UserRepo + Clone,
    R: RefreshTokenRepo + Clone,
{
    logger::log_user_login_attempt(&headers, &request.email);
    let email = users::service::Email::parse(&request.email).map_err(|_| ApiError::invalid_credentials())?;
    let cmd = LoginCommand {
        email: email.clone(),
        password: request.password,
    };
    let session = state.service.login(&state.context, cmd).await.map_err(|error| {
        if matches!(error, AuthError::InvalidCredentials) {
            logger::log_invalid_password(&headers, email.as_str());
        }
        ApiError::from(error)
    })?;

    logger::log_user_login_success(&headers, session.user.email.as_str());
    let body = LoginResponse {
        user: (&session.user).into(),
    };
    Ok(tokens::create_response_with_auth_cookies(
        &state.context,
        &body,
        Some(&session.access_token.value),
        Some(&session.refresh_token.value),
    )?)
}

pub async fn logout<UR, R>(
    State(state): State<AuthState<UR, R>>,
    req: Request<Body>,
) -> Result<impl IntoResponse, ApiError>
where
    UR: UserRepo + Clone,
    R: RefreshTokenRepo + Clone,
{
    let refresh_token = tokens::get_refresh_token_from_cookie(&req).ok();
    state.service
        .revoke_refresh_from_request(&state.context, refresh_token)
        .await?;

    let response = axum::http::Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Body::empty())
        .map_err(|_| ApiError::internal())?;
    Ok(tokens::add_auth_cookies(&state.context, response, None, None)?)
}

pub async fn refresh<UR, R>(
    State(state): State<AuthState<UR, R>>,
    req: Request<Body>,
) -> Result<impl IntoResponse, ApiError>
where
    UR: UserRepo + Clone,
    R: RefreshTokenRepo + Clone,
{
    let refresh_token = tokens::get_refresh_token_from_cookie(&req)?;
    let session = state.service
        .refresh(&state.context, refresh_token)
        .await
        .map_err(ApiError::from)?;

    logger::log_token_refresh(
        req.headers(),
        session.user.id.0,
        &session.old_jti,
        &session.user.id.0.to_string(),
    );

    let body = RefreshResponse {
        expires_in: session.expires_in,
        user: (&session.user).into(),
    };
    Ok(tokens::create_response_with_auth_cookies(
        &state.context,
        &body,
        Some(&session.access_token.value),
        Some(&session.refresh_token.value),
    )?)
}
