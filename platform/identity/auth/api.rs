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

use crate::common::ApiError;
use crate::common::ArcContext;
use crate::identity::auth;
use crate::identity::users;
use crate::internal::logger;
use crate::internal::tokens;

pub fn router<UR, R>(ctx: ArcContext, auth_service: auth::domain::Service<UR, R>) -> Router<ArcContext>
where
    UR: users::domain::UserRepo + Clone + 'static,
    R: auth::domain::RefreshTokenRepo + Clone + 'static,
{
    Router::new()
        .route("/auth/login", post(login::<UR, R>))
        .route("/auth/logout", post(logout::<UR, R>))
        .route("/auth/refresh", post(refresh::<UR, R>))
        .with_state((ctx, auth_service))
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

impl From<&crate::identity::users::domain::User> for UserResponse {
    fn from(user: &crate::identity::users::domain::User) -> Self {
        Self {
            id: user.id.0,
            email: user.email.as_str().to_string(),
            tenant_id: user.tenant_id.0,
        }
    }
}

impl From<auth::domain::AuthError> for ApiError {
    fn from(error: auth::domain::AuthError) -> Self {
        match error {
            auth::domain::AuthError::InvalidCredentials => Self::invalid_credentials(),
            auth::domain::AuthError::InvalidToken => Self::invalid_token(),
            auth::domain::AuthError::TokenOperationFailed(token_error) => token_error.into_api_error(),
            auth::domain::AuthError::JwtOperationFailed(jwt_error) => jwt_error.into_api_error(),
            auth::domain::AuthError::UserAlreadyExists => Self::user_already_exists(),
            // AuthError::UserOperationFailed(user_error) => user_error.into(),
            auth::domain::AuthError::PasswordHashingFailed(_) | auth::domain::AuthError::Database(_) | auth::domain::AuthError::Internal(_) => {
                tracing::error!("auth error: {error}");
                Self::internal()
            }
        }
    }
}

pub async fn login<UR, R>(
    State((context, service)): State<(ArcContext, auth::domain::Service<UR, R>)>,
    headers: HeaderMap,
    Json(request): Json<LoginRequest>,
) -> Result<impl IntoResponse, ApiError>
where
    UR: users::domain::UserRepo + Clone,
    R: auth::domain::RefreshTokenRepo + Clone,
{
    logger::log_user_login_attempt(&headers, &request.email);
    let email = users::domain::Email::parse(&request.email).map_err(|_| ApiError::invalid_credentials())?;
    let cmd = auth::domain::LoginCommand {
        email: email.clone(),
        password: request.password,
    };
    let session = service.login(&context, cmd).await.map_err(|error| {
        if matches!(error, auth::domain::AuthError::InvalidCredentials) {
            logger::log_invalid_password(&headers, email.as_str());
        }
        ApiError::from(error)
    })?;

    logger::log_user_login_success(&headers, session.user.email.as_str());
    let body = LoginResponse {
        user: (&session.user).into(),
    };
    Ok(tokens::create_response_with_auth_cookies(
        &context,
        &body,
        Some(&session.access_token.value),
        Some(&session.refresh_token.value),
    )?)
}

pub async fn logout<UR, R>(
    State((context, service)): State<(ArcContext, auth::domain::Service<UR, R>)>,
    req: Request<Body>,
) -> Result<impl IntoResponse, ApiError>
where
    UR: users::domain::UserRepo + Clone,
    R: auth::domain::RefreshTokenRepo + Clone,
{
    let refresh_token = tokens::get_refresh_token_from_cookie(&req).ok();
    service
        .revoke_refresh_from_request(&context, refresh_token)
        .await?;

    let response = axum::http::Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Body::empty())
        .map_err(|_| ApiError::internal())?;
    Ok(tokens::add_auth_cookies(&context, response, None, None)?)
}

pub async fn refresh<UR, R>(
    State((context, service)): State<(ArcContext, auth::domain::Service<UR, R>)>,
    req: Request<Body>,
) -> Result<impl IntoResponse, ApiError>
where
    UR: users::domain::UserRepo + Clone,
    R: auth::domain::RefreshTokenRepo + Clone,
{
    let refresh_token = tokens::get_refresh_token_from_cookie(&req)?;
    let session = service
        .refresh(&context, refresh_token)
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
        &context,
        &body,
        Some(&session.access_token.value),
        Some(&session.refresh_token.value),
    )?)
}
