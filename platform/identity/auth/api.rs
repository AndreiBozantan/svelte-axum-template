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

use crate::common;
use crate::identity::auth;
use crate::identity::tokens as identity_tokens;
use crate::identity::users;
use crate::internal::logger;
use crate::internal::tokens;

pub fn router<UR, TR>(context: common::ArcContext, service: auth::Service<UR, TR>) -> Router<common::ArcContext>
where
    UR: users::Repository + Clone + 'static,
    TR: identity_tokens::Repository + Clone + 'static,
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
    UR: users::Repository + Clone + 'static,
    TR: identity_tokens::Repository + Clone + 'static,
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

impl From<&crate::identity::users::User> for UserResponse {
    fn from(user: &crate::identity::users::User) -> Self {
        Self {
            id: user.id.0,
            email: user.email.as_str().to_string(),
            tenant_id: user.tenant_id.0,
        }
    }
}

impl From<auth::AuthError> for common::ApiError {
    fn from(error: auth::AuthError) -> Self {
        match error {
            auth::AuthError::InvalidCredentials => Self::invalid_credentials(),
            auth::AuthError::InvalidToken => Self::invalid_token(),
            auth::AuthError::TokenOperationFailed(token_error) => token_error.into_api_error(),
            auth::AuthError::JwtOperationFailed(jwt_error) => jwt_error.into_api_error(),
            auth::AuthError::UserAlreadyExists => Self::user_already_exists(),
            // AuthError::UserOperationFailed(user_error) => user_error.into(),
            auth::AuthError::PasswordHashingFailed(_) | auth::AuthError::Database(_) | auth::AuthError::Internal(_) => {
                tracing::error!("auth error: {error}");
                Self::internal()
            }
        }
    }
}

async fn login<UR, TR>(
    State(AppState { context, service }): State<AppState<UR, TR>>,
    headers: HeaderMap,
    Json(request): Json<LoginRequest>,
) -> Result<impl IntoResponse, common::ApiError>
where
    UR: users::Repository + Clone,
    TR: identity_tokens::Repository + Clone,
{
    logger::log_user_login_attempt(&headers, &request.email);
    let email = common::Email::parse(&request.email).map_err(|_| common::ApiError::invalid_credentials())?;
    let cmd = auth::LoginCommand {
        email: email.clone(),
        password: request.password,
    };
    let session = service.login(&context, cmd).await.map_err(|error| {
        if matches!(error, auth::AuthError::InvalidCredentials) {
            logger::log_invalid_password(&headers, email.as_str());
        }
        common::ApiError::from(error)
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

async fn logout<UR, TR>(
    State(AppState { context, service }): State<AppState<UR, TR>>,
    req: Request<Body>,
) -> Result<impl IntoResponse, common::ApiError>
where
    UR: users::Repository + Clone,
    TR: identity_tokens::Repository + Clone,
{
    let refresh_token = tokens::get_refresh_token_from_cookie(&req).ok();
    service.revoke_refresh_from_request(&context, refresh_token).await?;

    let response = axum::http::Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Body::empty())
        .map_err(|_| common::ApiError::internal())?;
    Ok(tokens::add_auth_cookies(&context, response, None, None)?)
}

async fn refresh<UR, TR>(
    State(AppState { context, service }): State<AppState<UR, TR>>,
    req: Request<Body>,
) -> Result<impl IntoResponse, common::ApiError>
where
    UR: users::Repository + Clone,
    TR: identity_tokens::Repository + Clone,
{
    let refresh_token = tokens::get_refresh_token_from_cookie(&req)?;
    let session = service
        .refresh(&context, refresh_token)
        .await
        .map_err(common::ApiError::from)?;

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
