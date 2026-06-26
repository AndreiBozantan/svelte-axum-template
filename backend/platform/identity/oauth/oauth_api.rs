use axum;
use axum::extract::State;
use axum::http;
use axum::response::IntoResponse;
use tracing::info;
use tracing::warn;
use utoipax;

use crate::platform::api;
use crate::platform::common;
use crate::platform::cookies;
use crate::platform::crypto;

use crate::platform::identity::auth;
use crate::platform::identity::oauth;

pub fn router(service: oauth::Service) -> utoipax::router::OpenApiRouter<common::ArcContext> {
    use utoipax::routes;
    utoipax::router::OpenApiRouter::new()
        .routes(routes!(google_auth_init))
        .routes(routes!(google_auth_callback))
        .with_state(service)
}

impl From<oauth::Error> for api::Error {
    fn from(error: oauth::Error) -> Self {
        #[allow(clippy::enum_glob_use)]
        use oauth::Error::*;

        #[allow(clippy::match_same_arms)]
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

#[utoipa::path(
    get,
    path = "/oauth/google",
    params(
        ("redirect_url" = Option<String>, Query, description = "Client redirect URL after login")
    ),
    responses(
        (status = 303, description = "Redirect to Google authorization page")
    )
)]
async fn google_auth_init(
    State(service): State<oauth::Service>,
    params: api::Query<std::collections::BTreeMap<String, String>>,
) -> Result<impl IntoResponse, api::Error> {
    let redirect_url = params.data().get("redirect_url").cloned();
    info!(provider = "google", ?redirect_url, "sso_initiate");

    let (auth_url, state_jwt) = service.begin_google_flow(redirect_url).map_err(|err| {
        warn!(error = %err, provider = "google", "sso_initiate_failed");
        err
    })?;
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

#[utoipa::path(
    get,
    path = "/oauth/google/callback",
    params(
        ("code" = String, Query, description = "Google authorization code"),
        ("state" = String, Query, description = "CSRF state token")
    ),
    responses(
        (status = 303, description = "Redirect to client final landing URL")
    )
)]
async fn google_auth_callback(
    State(service): State<oauth::Service>,
    headers: http::HeaderMap,
    params: api::Query<oauth::GoogleCallbackRequest>,
) -> Result<impl IntoResponse, api::Error> {
    let params = params.data();
    let oauth_state_cookie = cookies::get_cookie_value_from_headers(&headers, "oauth_state").ok_or_else(|| {
        info!("oauth_state_cookie_missing");
        api::Error::sso_failed()
    })?;

    let (user_info, redirect_url) = service
        .complete_google_callback(&params.code, &params.state, &oauth_state_cookie)
        .await
        .map_err(|err| {
            warn!(error = %err, provider = "google", "sso_callback_failed");
            err
        })?;
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

    let email = common::Email::parse(&user_info.email).ok_or_else(|| {
        warn!(
            email_hash = %crypto::get_hash_as_hex(&user_info.email),
            provider = "google",
            "invalid_email_format"
        );
        api::Error::sso_failed()
    })?;
    let cmd = auth::OAuthLoginCommand {
        email,
        sso_provider: "google".to_string(),
        sso_id: user_info.id,
    };

    let session = service.auth.login_oauth(cmd).await.map_err(|err| {
        warn!(error = %err, provider = "google", "sso_login_failed");
        err
    })?;

    #[allow(clippy::match_wildcard_for_single_variants)]
    oauth::validate_redirect_path(&redirect_url).map_err(|err| {
        warn!(error = %err, "invalid_final_redirect_url");
        api::Error::sso_failed()
    })?;

    let response = axum::response::Redirect::to(&redirect_url).into_response();
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
