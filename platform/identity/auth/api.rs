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

use super::repo::SqliteRefreshTokenRepo;
use super::service::{AuthError, AuthService, DefaultAuthService, LoginCommand};
use crate::common::ApiError;
use crate::common::ArcContext;
use crate::identity::users;
use crate::internal::logger;
use crate::internal::tokens;

pub fn router() -> Router<ArcContext> {
    Router::new()
        .route("/auth/login", post(login))
        .route("/auth/logout", post(logout))
        .route("/auth/refresh", post(refresh))
}

const fn auth_service() -> DefaultAuthService {
    AuthService::new(
        users::service::UserService::new(users::repo::SqliteUserRepo),
        SqliteRefreshTokenRepo,
    )
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

pub async fn login(
    State(context): State<ArcContext>,
    headers: HeaderMap,
    Json(request): Json<LoginRequest>,
) -> Result<impl IntoResponse, ApiError> {
    logger::log_user_login_attempt(&headers, &request.email);
    let email = users::service::Email::parse(&request.email).map_err(|_| ApiError::invalid_credentials())?;
    let cmd = LoginCommand {
        email: email.clone(),
        password: request.password,
    };
    let session = auth_service().login(&context, cmd).await.map_err(|error| {
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
        &context,
        &body,
        Some(&session.access_token.value),
        Some(&session.refresh_token.value),
    )?)
}

pub async fn logout(State(context): State<ArcContext>, req: Request<Body>) -> Result<impl IntoResponse, ApiError> {
    let refresh_token = tokens::get_refresh_token_from_cookie(&req).ok();
    auth_service()
        .revoke_refresh_from_request(&context, refresh_token)
        .await?;

    let response = axum::http::Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Body::empty())
        .map_err(|_| ApiError::internal())?;
    Ok(tokens::add_auth_cookies(&context, response, None, None)?)
}

pub async fn refresh(State(context): State<ArcContext>, req: Request<Body>) -> Result<impl IntoResponse, ApiError> {
    let refresh_token = tokens::get_refresh_token_from_cookie(&req)?;
    let session = auth_service()
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
