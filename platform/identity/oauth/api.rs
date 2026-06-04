use axum::Router;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::routing::get;

use crate::common::ApiError;
use crate::common::ArcContext;
use crate::identity::auth::repo::SqliteRefreshTokenRepo;
use crate::identity::auth::service::AuthService;
use crate::identity::users::repo::SqliteUserRepo;
use crate::identity::users::service::{Email, LinkSsoUserCommand, TenantId, UserService};
use crate::internal::logger;
use crate::internal::tokens;

use super::service::{GoogleCallbackRequest, OAuthError, begin_google_flow, complete_google_callback};

const SSO_DEFAULT_TENANT_ID: i64 = 0;

const fn auth_service() -> crate::identity::auth::service::DefaultAuthService {
    AuthService::new(UserService::new(SqliteUserRepo), SqliteRefreshTokenRepo)
}

impl From<OAuthError> for ApiError {
    fn from(error: OAuthError) -> Self {
        match error {
            OAuthError::UnverifiedEmail | OAuthError::InvalidUserInfo => Self::invalid_credentials(),
            OAuthError::CsrfValidationFailed
            | OAuthError::SessionExpired
            | OAuthError::OAuth2RequestFailed(_)
            | OAuthError::InvalidConfig(_)
            | OAuthError::InvalidRedirectUrl => Self::sso_failed(),
            OAuthError::UserInfoRetrievalFailed(_) | OAuthError::Internal(_) => {
                tracing::error!("oauth error: {error}");
                Self::internal()
            }
        }
    }
}

pub fn router() -> Router<ArcContext> {
    Router::new()
        .route("/oauth/google", get(google_auth_init))
        .route("/oauth/google/callback", get(google_auth_callback))
}

pub async fn google_auth_init(
    State(context): State<ArcContext>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<std::collections::BTreeMap<String, String>>,
) -> Result<impl IntoResponse, ApiError> {
    let redirect_url = params.get("redirect_url").cloned();
    logger::log_oauth_flow_initiated(&headers, redirect_url.as_ref(), "google");

    let (auth_url, state_jwt) = begin_google_flow(&context, redirect_url)?;
    logger::log_oauth_redirecting(&headers, &auth_url, "google");

    let mut response = axum::response::Redirect::to(auth_url.as_str()).into_response();
    let cookie_max_age = context.settings.oauth.session_timeout_minutes * 60;
    let cookie = format!(
        "oauth_state={state_jwt}; HttpOnly; Secure; SameSite=Lax; Path=/api/oauth/google/callback; Max-Age={cookie_max_age}"
    );
    let cookie_val = axum::http::HeaderValue::from_str(&cookie).map_err(|_| ApiError::internal())?;
    response
        .headers_mut()
        .insert(axum::http::header::SET_COOKIE, cookie_val);
    Ok(response)
}

pub async fn google_auth_callback(
    State(context): State<ArcContext>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<GoogleCallbackRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let oauth_state_cookie = tokens::get_cookie_value_from_headers(&headers, "oauth_state").ok_or_else(|| {
        logger::log_cookie_error(&headers, "missing_oauth_state");
        ApiError::sso_failed()
    })?;

    let (user_info, redirect_url) =
        complete_google_callback(&context, &headers, &params.code, &params.state, oauth_state_cookie).await?;

    if !user_info.verified_email {
        logger::log_oauth_security_violation(&headers, &params.state, &user_info.email, "unverified_email", "google");
        return Err(ApiError::InvalidCredentials);
    }

    logger::log_oauth_user_authenticated(&headers, &params.state, &user_info.email, "google");

    let email = Email::parse(&user_info.email).map_err(|_| ApiError::invalid_credentials())?;
    let user = UserService::new(SqliteUserRepo)
        .link_sso_user(
            &context.db,
            LinkSsoUserCommand {
                email,
                tenant_id: TenantId(SSO_DEFAULT_TENANT_ID),
                sso_provider: "google".to_string(),
                sso_id: user_info.id,
            },
        )
        .await?;

    let session = auth_service().issue_session(&context, user).await?;

    let final_redirect_url = redirect_url.as_deref().unwrap_or("/");
    let response = axum::response::Redirect::to(final_redirect_url).into_response();
    let mut response = tokens::add_auth_cookies(
        &context,
        response,
        Some(&session.access_token.value),
        Some(&session.refresh_token.value),
    )?;

    let clear_cookie = "oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/api/oauth/google/callback; Max-Age=0";
    let cookie_val = axum::http::HeaderValue::from_static(clear_cookie);
    response
        .headers_mut()
        .append(axum::http::header::SET_COOKIE, cookie_val);

    Ok(response)
}
