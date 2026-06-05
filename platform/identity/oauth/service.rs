use chrono::Utc;
use jsonwebtoken;
use oauth2;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;
use url::Url;

use crate::common::ArcContext;
use crate::config;
use crate::internal::logger;
use crate::internal::tokens;

#[derive(Debug, Error)]
pub enum OAuthError {
    #[error("internal error: {0}")]
    Internal(String),

    #[error("OAuth2 request failed: {0}")]
    OAuth2RequestFailed(
        #[from]
        oauth2::RequestTokenError<
            oauth2::HttpClientError<oauth2::reqwest::Error>,
            oauth2::StandardErrorResponse<oauth2::basic::BasicErrorResponseType>,
        >,
    ),

    #[error("OAuth provider configuration error: {0}")]
    InvalidConfig(String),

    #[error("User info retrieval API call failed: {0}")]
    UserInfoRetrievalFailed(#[from] reqwest::Error),

    #[error("CSRF token validation failed")]
    CsrfValidationFailed,

    #[error("OAuth session expired or invalid")]
    SessionExpired,

    #[error("Invalid redirect URL")]
    InvalidRedirectUrl,

    #[error("User info returned by provider was invalid")]
    InvalidUserInfo,

    #[error("email address is not verified")]
    UnverifiedEmail,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GoogleUserInfo {
    pub id: String,
    pub email: String,
    pub verified_email: bool,
    pub name: String,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub picture: Option<String>,
    pub locale: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct GoogleCallbackRequest {
    pub code: String,
    pub state: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OAuthStateClaims {
    pub csrf_token_hash: String,
    pub redirect_url: Option<String>,
    pub iat: i64,
    pub exp: i64,
}

type GoogleOAuth2Client = oauth2::basic::BasicClient<
    oauth2::EndpointSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointSet,
>;

fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub fn validate_google_config(config: &config::OAuthSettings) -> Result<(), OAuthError> {
    if config.google_client_id.is_empty() {
        return Err(OAuthError::InvalidConfig(
            "Google Client ID is not configured".to_string(),
        ));
    }
    if config.google_client_secret.is_empty() {
        return Err(OAuthError::InvalidConfig(
            "Google Client Secret is not configured".to_string(),
        ));
    }
    if config.google_redirect_uri.is_empty() {
        return Err(OAuthError::InvalidConfig(
            "Google Redirect URI is not configured".to_string(),
        ));
    }

    let parsed: Url = config
        .google_redirect_uri
        .parse()
        .map_err(|_| OAuthError::InvalidConfig("Invalid Google Redirect URI format".to_string()))?;

    let host = parsed.host_str().unwrap_or("");
    let is_localhost = host == "localhost" || host == "127.0.0.1" || host == "::1";
    if parsed.scheme() != "https" && !is_localhost {
        logger::log_invalid_config("oauth.google_redirect_uri", &config.google_redirect_uri);
        return Err(OAuthError::InvalidConfig(
            "Google Redirect URI must use HTTPS in non-localhost environments".to_string(),
        ));
    }

    Ok(())
}

fn create_google_client(config: &config::OAuthSettings) -> Result<GoogleOAuth2Client, OAuthError> {
    validate_google_config(config)?;
    let redirect_url = oauth2::RedirectUrl::new(config.google_redirect_uri.clone())
        .map_err(|_| OAuthError::InvalidConfig("Invalid Google Redirect URI format".to_string()))?;
    let auth_url = oauth2::AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())
        .map_err(|_| OAuthError::InvalidConfig("Invalid Google auth URL".to_string()))?;
    let token_url = oauth2::TokenUrl::new("https://www.googleapis.com/oauth2/v3/token".to_string())
        .map_err(|_| OAuthError::InvalidConfig("Invalid Google token URL".to_string()))?;

    let client = oauth2::basic::BasicClient::new(oauth2::ClientId::new(config.google_client_id.clone()))
        .set_client_secret(oauth2::ClientSecret::new(config.google_client_secret.clone()))
        .set_auth_uri(auth_url)
        .set_token_uri(token_url)
        .set_redirect_uri(redirect_url);
    Ok(client)
}

pub fn begin_google_flow(context: &ArcContext, redirect_url: Option<String>) -> Result<(Url, String), OAuthError> {
    let redirect_url = if let Some(url) = redirect_url
        && validate_redirect_path(&url).is_ok()
    {
        Some(url)
    } else {
        Some("/".to_string())
    };

    let client = create_google_client(&context.settings.oauth)?;
    let (auth_url, csrf_token) = client
        .authorize_url(oauth2::CsrfToken::new_random)
        .add_scope(oauth2::Scope::new("openid".to_string()))
        .add_scope(oauth2::Scope::new("email".to_string()))
        .add_scope(oauth2::Scope::new("profile".to_string()))
        .url();

    let now = Utc::now().timestamp();
    let timeout_minutes = i64::from(context.settings.oauth.session_timeout_minutes);
    let claims = OAuthStateClaims {
        csrf_token_hash: tokens::get_token_hash_as_hex(csrf_token.secret()),
        iat: now,
        exp: now + (timeout_minutes * 60),
        redirect_url,
    };

    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    let state_jwt = jsonwebtoken::encode(&header, &claims, &context.jwt.encoding_key).map_err(|error| {
        logger::log_internal_error(&error, "encode_oauth_state");
        OAuthError::InvalidConfig("Failed to encode OAuth state JWT".to_string())
    })?;

    Ok((auth_url, state_jwt))
}

pub async fn complete_google_callback(
    context: &ArcContext,
    headers: &axum::http::HeaderMap,
    code: &str,
    state: &str,
    oauth_state_cookie: &str,
) -> Result<(GoogleUserInfo, Option<String>), OAuthError> {
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.validate_exp = true;
    validation.leeway = 5;

    let token_data =
        jsonwebtoken::decode::<OAuthStateClaims>(oauth_state_cookie, &context.jwt.decoding_key, &validation).map_err(
            |error| {
                if matches!(error.kind(), jsonwebtoken::errors::ErrorKind::ExpiredSignature) {
                    logger::log_signture_expired(headers);
                    OAuthError::SessionExpired
                } else {
                    logger::log_internal_error(&error, "decode_oauth_state");
                    OAuthError::CsrfValidationFailed
                }
            },
        )?;

    let incoming_hash = tokens::get_token_hash_as_hex(state);
    if !constant_time_eq(&token_data.claims.csrf_token_hash, &incoming_hash) {
        logger::log_csrf_mismatch(None, &token_data.claims.csrf_token_hash, &incoming_hash);
        return Err(OAuthError::CsrfValidationFailed);
    }

    let client = create_google_client(&context.settings.oauth)?;
    let oauth_client = oauth2::reqwest::ClientBuilder::new().build().map_err(|error| {
        logger::log_internal_error(&error, "create_oauth_client");
        OAuthError::Internal(format!("Failed to create HTTP client for OAuth: {error}"))
    })?;

    let token_result = client
        .exchange_code(oauth2::AuthorizationCode::new(code.to_string()))
        .request_async(&oauth_client)
        .await
        .map_err(|error| {
            logger::log_internal_error(&error, "oauth_exchange_code");
            OAuthError::OAuth2RequestFailed(error)
        })?;

    let access_token = oauth2::TokenResponse::access_token(&token_result).secret();
    let response = context
        .http_client
        .get("https://www.googleapis.com/oauth2/v2/userinfo")
        .bearer_auth(access_token)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await?;

    if !response.status().is_success() {
        logger::log_provider_api_error(response.status(), "google");
        return Err(OAuthError::InvalidConfig(
            "OAuth provider returned an error".to_string(),
        ));
    }

    let user_info: GoogleUserInfo = response.json().await?;

    if user_info.email.is_empty() {
        logger::log_invalid_user_info("email", &user_info.email, "google");
        return Err(OAuthError::InvalidUserInfo);
    }

    if !user_info.verified_email {
        logger::log_invalid_user_info("verified_email", "false", "google");
        return Err(OAuthError::UnverifiedEmail);
    }

    if user_info.id.is_empty() {
        logger::log_invalid_user_info("id", &user_info.id, "google");
        return Err(OAuthError::InvalidUserInfo);
    }

    Ok((user_info, token_data.claims.redirect_url))
}

fn validate_redirect_path(path: &str) -> Result<(), OAuthError> {
    if path.len() > 512 {
        return Err(OAuthError::InvalidRedirectUrl);
    }
    if !path.starts_with('/') || path.starts_with("//") || path.contains("://") {
        return Err(OAuthError::InvalidRedirectUrl);
    }
    Ok(())
}
