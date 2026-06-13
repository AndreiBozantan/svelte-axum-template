use axum;
use axum::extract::State;
use axum::http;
use axum::response::IntoResponse;
use tracing::info;
use tracing::warn;

use crate::platform::api;
use crate::platform::common;
use crate::platform::cookies;
use crate::platform::crypto;

use crate::platform::identity::auth;
use crate::platform::identity::oauth;
use crate::platform::identity::tokens;
use crate::platform::identity::users;

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

impl From<oauth::Error> for api::Error {
    fn from(error: oauth::Error) -> Self {
        #[allow(clippy::enum_glob_use)]
        use oauth::Error::*;

        match error {
            InvalidUserInfo => Self::invalid_credentials(),
            UnverifiedEmail => Self::invalid_credentials(),
            CsrfValidationFailed(_) => Self::sso_failed(),
            CsrfMismatch => Self::sso_failed(),
            SessionExpired => Self::sso_failed(),
            OAuth2RequestFailed(_) => Self::sso_failed(),
            InvalidConfig(_) => Self::sso_failed(),
            InvalidRedirectUrl => Self::sso_failed(),
            UserInfoRetrievalFailed(_) => Self::internal(),
            InternalFault(_) => Self::internal(),
        }
    }
}

async fn google_auth_init<UR, TR>(
    State(service): State<oauth::Service<UR, TR>>,
    params: api::Query<std::collections::BTreeMap<String, String>>,
) -> Result<impl IntoResponse, api::Error>
where
    UR: users::TRepository + Clone + 'static,
    TR: tokens::TRepository + Clone + 'static,
{
    let redirect_url = params.data().get("redirect_url").cloned();
    info!(provider = "google", ?redirect_url, "sso_initiate");

    let (auth_url, state_jwt) = service.begin_google_flow(redirect_url)?;
    info!(provider = "google", %auth_url, "sso_redirect");

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
    let oauth_state_cookie = cookies::get_cookie_value_from_headers(&headers, "oauth_state").ok_or_else(|| {
        info!("oauth_state_cookie_missing");
        api::Error::sso_failed()
    })?;

    let (user_info, redirect_url) = service
        .complete_google_callback(&params.code, &params.state, &oauth_state_cookie)
        .await?;
    if !user_info.verified_email {
        warn!(
            state_hash = %crypto::get_hash_as_hex(&params.state),
            email_hash = %crypto::get_hash_as_hex(&user_info.email),
            provider = "google",
            "unverified_email"
        );
        return Err(api::Error::sso_failed());
    }

    info!(
        state_hash = %crypto::get_hash_as_hex(&params.state),
        email_hash = %crypto::get_hash_as_hex(&user_info.email),
        provider = "google",
        "success"
    );

    let email = common::Email::parse(&user_info.email).ok_or_else(api::Error::sso_failed)?;
    let cmd = auth::OAuthLoginCommand {
        email,
        sso_provider: "google".to_string(),
        sso_id: user_info.id,
    };

    let session = service.auth.login_oauth(cmd).await?;
    let final_redirect_url = redirect_url.as_deref().unwrap_or("/");
    let response = axum::response::Redirect::to(final_redirect_url).into_response();
    let mut response = cookies::add_auth_cookies(
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
