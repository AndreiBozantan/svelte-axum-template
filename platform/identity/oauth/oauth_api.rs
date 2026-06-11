use axum;
use axum::extract::State;
use axum::http;
use axum::response::IntoResponse;

use crate::api;
use crate::common;
use crate::identity::auth;
use crate::identity::oauth;
use crate::identity::tokens;
use crate::identity::users;
use crate::internal::logger;

pub fn router<UR, TR>(service: oauth::Service<UR, TR>) -> axum::Router<common::ArcContext>
where
    UR: users::TRepository + Clone + 'static,
    TR: tokens::TRepository + Clone + 'static,
{
    use axum::routing::get;
    axum::Router::new()
        .route("/oauth/google", get(google_auth_init::<UR, TR>))
        .route("/oauth/google/callback", get(google_auth_callback::<UR, TR>))
        .with_state(service)
}

#[allow(clippy::match_same_arms)]
impl From<oauth::Error> for api::Error {
    fn from(error: oauth::Error) -> Self {
        tracing::error!("oauth error: {error}");
        match error {
            oauth::Error::UnverifiedEmail | oauth::Error::InvalidUserInfo => Self::invalid_credentials(),
            oauth::Error::CsrfValidationFailed(_) => Self::sso_failed(),
            oauth::Error::CsrfMismatch => Self::sso_failed(),
            oauth::Error::SessionExpired => Self::sso_failed(),
            oauth::Error::OAuth2RequestFailed(_) => Self::sso_failed(),
            oauth::Error::InvalidConfig(_) => Self::sso_failed(),
            oauth::Error::InvalidRedirectUrl => Self::sso_failed(),
            oauth::Error::UserInfoRetrievalFailed(_) => Self::internal(),
            oauth::Error::InternalFault(_) => Self::internal(),
        }
    }
}

async fn google_auth_init<UR, TR>(
    State(service): State<oauth::Service<UR, TR>>,
    headers: http::HeaderMap,
    params: api::Query<std::collections::BTreeMap<String, String>>,
) -> Result<impl IntoResponse, api::Error>
where
    UR: users::TRepository + Clone + 'static,
    TR: tokens::TRepository + Clone + 'static,
{
    let redirect_url = params.data().get("redirect_url").cloned();
    logger::log_oauth_flow_initiated(&headers, redirect_url.as_ref(), "google");

    let (auth_url, state_jwt) = service.begin_google_flow(redirect_url)?;
    logger::log_oauth_redirecting(&headers, &auth_url, "google");

    let mut response = axum::response::Redirect::to(auth_url.as_str()).into_response();
    let cookie_max_age = service.context.settings.oauth.session_timeout_minutes * 60;
    let cookie = format!(
        "oauth_state={state_jwt}; HttpOnly; Secure; SameSite=Lax; Path=/api/oauth/google/callback; Max-Age={cookie_max_age}"
    );
    let cookie_val = axum::http::HeaderValue::from_str(&cookie)?;
    response
        .headers_mut()
        .insert(axum::http::header::SET_COOKIE, cookie_val);
    Ok(response)
}

async fn google_auth_callback<UR, TR>(
    State(service): State<oauth::Service<UR, TR>>,
    headers: http::HeaderMap,
    params: api::Query<oauth::GoogleCallbackRequest>,
) -> Result<impl IntoResponse, api::Error>
where
    UR: users::TRepository + Clone + 'static,
    TR: tokens::TRepository + Clone + 'static,
{
    let params = params.data();
    let oauth_state_cookie =
        tokens::utils::get_cookie_value_from_headers(&headers, "oauth_state").ok_or_else(|| {
            logger::log_cookie_error(&headers, "missing_oauth_state");
            api::Error::sso_failed()
        })?;

    let (user_info, redirect_url) = service
        .complete_google_callback(&params.code, &params.state, &oauth_state_cookie)
        .await?;
    if !user_info.verified_email {
        logger::log_oauth_security_violation(&headers, &params.state, &user_info.email, "unverified_email", "google");
        return Err(api::Error::invalid_credentials());
    }

    logger::log_oauth_user_authenticated(&headers, &params.state, &user_info.email, "google");

    let email = common::Email::parse(&user_info.email).ok_or_else(api::Error::invalid_credentials)?;
    let cmd = auth::OAuthLoginCommand {
        email,
        sso_provider: "google".to_string(),
        sso_id: user_info.id,
    };

    let session = service.auth.login_oauth(cmd).await?;
    let final_redirect_url = redirect_url.as_deref().unwrap_or("/");
    let response = axum::response::Redirect::to(final_redirect_url).into_response();
    let mut response = tokens::utils::add_auth_cookies(
        &service.context.settings.jwt,
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
