use axum::Router;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::IntoResponse;

use crate::api;
use crate::common;
use crate::identity::auth;
use crate::identity::tokens;
use crate::identity::users;
use crate::internal::logger;

pub fn router<UR, TR>(ctx: common::ArcContext, auth_service: auth::Service<UR, TR>) -> Router<common::ArcContext>
where
    UR: users::TRepository + Clone + 'static,
    TR: tokens::TRepository + Clone + 'static,
{
    use axum::routing::get;
    Router::new()
        .route("/oauth/google", get(google_auth_init::<UR, TR>))
        .route("/oauth/google/callback", get(google_auth_callback::<UR, TR>))
        .with_state(AppState { ctx, auth_service })
}

#[derive(Clone)]
struct AppState<UR, TR>
where
    UR: users::TRepository + Clone + 'static,
    TR: tokens::TRepository + Clone + 'static,
{
    pub ctx: common::ArcContext,
    pub auth_service: auth::Service<UR, TR>,
}

impl From<super::Error> for api::Error {
    fn from(error: super::Error) -> Self {
        match error {
            super::Error::UnverifiedEmail | super::Error::InvalidUserInfo => Self::invalid_credentials(),
            super::Error::CsrfValidationFailed
            | super::Error::SessionExpired
            | super::Error::OAuth2RequestFailed(_)
            | super::Error::InvalidConfig(_)
            | super::Error::InvalidRedirectUrl => Self::sso_failed(),
            super::Error::UserInfoRetrievalFailed(_) | super::Error::Internal(_) => {
                tracing::error!("oauth error: {error}");
                Self::internal()
            }
        }
    }
}

async fn google_auth_init<UR, TR>(
    State(AppState { ctx, .. }): State<AppState<UR, TR>>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<std::collections::BTreeMap<String, String>>,
) -> Result<impl IntoResponse, api::Error>
where
    UR: users::TRepository + Clone,
    TR: tokens::TRepository + Clone,
{
    let redirect_url = params.get("redirect_url").cloned();
    logger::log_oauth_flow_initiated(&headers, redirect_url.as_ref(), "google");

    let (auth_url, state_jwt) = super::begin_google_flow(&ctx, redirect_url)?;
    logger::log_oauth_redirecting(&headers, &auth_url, "google");

    let mut response = axum::response::Redirect::to(auth_url.as_str()).into_response();
    let cookie_max_age = ctx.settings.oauth.session_timeout_minutes * 60;
    let cookie = format!(
        "oauth_state={state_jwt}; HttpOnly; Secure; SameSite=Lax; Path=/api/oauth/google/callback; Max-Age={cookie_max_age}"
    );
    let cookie_val = axum::http::HeaderValue::from_str(&cookie).map_err(|_| api::Error::internal())?;
    response
        .headers_mut()
        .insert(axum::http::header::SET_COOKIE, cookie_val);
    Ok(response)
}

async fn google_auth_callback<UR, TR>(
    State(AppState { ctx, auth_service }): State<AppState<UR, TR>>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<super::GoogleCallbackRequest>,
) -> Result<impl IntoResponse, api::Error>
where
    UR: users::TRepository + Clone,
    TR: tokens::TRepository + Clone,
{
    let oauth_state_cookie =
        tokens::utils::get_cookie_value_from_headers(&headers, "oauth_state").ok_or_else(|| {
            logger::log_cookie_error(&headers, "missing_oauth_state");
            api::Error::sso_failed()
        })?;

    let (user_info, redirect_url) =
        super::complete_google_callback(&ctx, &headers, &params.code, &params.state, oauth_state_cookie).await?;

    if !user_info.verified_email {
        logger::log_oauth_security_violation(&headers, &params.state, &user_info.email, "unverified_email", "google");
        return Err(api::Error::invalid_credentials());
    }

    logger::log_oauth_user_authenticated(&headers, &params.state, &user_info.email, "google");

    let email = common::Email::parse(&user_info.email)?;
    let cmd = auth::OAuthLoginCommand {
        email,
        sso_provider: "google".to_string(),
        sso_id: user_info.id,
    };

    let session = auth_service.login_oauth(&ctx, cmd).await?;
    let final_redirect_url = redirect_url.as_deref().unwrap_or("/");
    let response = axum::response::Redirect::to(final_redirect_url).into_response();
    let mut response = tokens::utils::add_auth_cookies(
        &ctx,
        response,
        Some(&session.access_token.value),
        Some(&session.refresh_token.value),
    )?;

    // clear oauth_state cookie by setting Max-Age=0
    let clear_cookie = "oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/api/oauth/google/callback; Max-Age=0";
    let cookie_val = axum::http::HeaderValue::from_static(clear_cookie);
    response
        .headers_mut()
        .append(axum::http::header::SET_COOKIE, cookie_val);

    Ok(response)
}
