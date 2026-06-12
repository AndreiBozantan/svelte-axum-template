use chrono::Utc;
use jsonwebtoken;
use oauth2;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;
use url::Url;

use crate::platform::common;
use crate::platform::config;
use crate::platform::crypto;
use crate::platform::logger;

use crate::platform::identity::auth;
use crate::platform::identity::tokens;
use crate::platform::identity::users;

#[derive(Debug, Error)]
pub enum Error {
    #[error("internal error: {0}")]
    InternalFault(String),

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

    #[error("CSRF token validation failed: {0}")]
    CsrfValidationFailed(#[source] jsonwebtoken::errors::Error),

    #[error("CSRF token mismatch")]
    CsrfMismatch,

    #[error("OAuth session expired or invalid")]
    SessionExpired,

    #[error("Invalid redirect URL")]
    InvalidRedirectUrl,

    #[error("User info returned by provider was invalid")]
    InvalidUserInfo,

    #[error("email address is not verified")]
    UnverifiedEmail,
}

impl From<jsonwebtoken::errors::Error> for Error {
    fn from(error: jsonwebtoken::errors::Error) -> Self {
        match error.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => Self::SessionExpired,
            _ => Self::CsrfValidationFailed(error),
        }
    }
}

impl From<url::ParseError> for Error {
    fn from(error: url::ParseError) -> Self {
        Self::InvalidConfig(format!("Invalid URL format: {error}"))
    }
}

impl From<oauth2::reqwest::Error> for Error {
    fn from(error: oauth2::reqwest::Error) -> Self {
        Self::InternalFault(format!("OAuth HTTP client request failed: {error}"))
    }
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

fn constant_time_eq(
    a: &str,
    b: &str,
) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub fn validate_google_config(config: &config::OAuthSettings) -> Result<(), Error> {
    if config.google_client_id.is_empty() {
        return Err(Error::InvalidConfig("Google Client ID is not configured".to_string()));
    }
    if config.google_client_secret.is_empty() {
        return Err(Error::InvalidConfig(
            "Google Client Secret is not configured".to_string(),
        ));
    }
    if config.google_redirect_uri.is_empty() {
        return Err(Error::InvalidConfig(
            "Google Redirect URI is not configured".to_string(),
        ));
    }

    let parsed: Url = config.google_redirect_uri.parse()?;

    let host = parsed.host_str().unwrap_or("");
    let is_localhost = host == "localhost" || host == "127.0.0.1" || host == "::1";
    if parsed.scheme() != "https" && !is_localhost {
        logger::log_invalid_config("oauth.google_redirect_uri", &config.google_redirect_uri);
        return Err(Error::InvalidConfig(
            "Google Redirect URI must use HTTPS in non-localhost environments".to_string(),
        ));
    }

    Ok(())
}

pub fn check_oauth_config(config: &config::OAuthSettings) {
    if let Err(error) = validate_google_config(config) {
        tracing::warn!("Google OAuth config is incomplete. {error}");
    }
}

fn create_google_client(config: &config::OAuthSettings) -> Result<GoogleOAuth2Client, Error> {
    validate_google_config(config)?;
    let redirect_url = oauth2::RedirectUrl::new(config.google_redirect_uri.clone())?;
    let auth_url = oauth2::AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())?;
    let token_url = oauth2::TokenUrl::new("https://www.googleapis.com/oauth2/v3/token".to_string())?;

    let client = oauth2::basic::BasicClient::new(oauth2::ClientId::new(config.google_client_id.clone()))
        .set_client_secret(oauth2::ClientSecret::new(config.google_client_secret.clone()))
        .set_auth_uri(auth_url)
        .set_token_uri(token_url)
        .set_redirect_uri(redirect_url);
    Ok(client)
}

#[derive(Clone)]
pub struct Service<UR: users::TRepository, TR: tokens::TRepository> {
    pub context: common::ArcContext,
    pub auth: auth::Service<UR, TR>,
}

impl<UR: users::TRepository, TR: tokens::TRepository> Service<UR, TR> {
    #[must_use]
    pub const fn new(
        context: common::ArcContext,
        auth_service: auth::Service<UR, TR>,
    ) -> Self {
        Self {
            context,
            auth: auth_service,
        }
    }

    pub fn begin_google_flow(
        &self,
        redirect_url: Option<String>,
    ) -> Result<(Url, String), Error> {
        let redirect_url = if let Some(url) = redirect_url
            && validate_redirect_path(&url).is_ok()
        {
            Some(url)
        } else {
            Some("/".to_string())
        };

        let client = create_google_client(&self.context.settings.oauth)?;
        let (auth_url, csrf_token) = client
            .authorize_url(oauth2::CsrfToken::new_random)
            .add_scope(oauth2::Scope::new("openid".to_string()))
            .add_scope(oauth2::Scope::new("email".to_string()))
            .add_scope(oauth2::Scope::new("profile".to_string()))
            .url();

        let now = Utc::now().timestamp();
        let timeout_minutes = i64::from(self.context.settings.oauth.session_timeout_minutes);
        let claims = OAuthStateClaims {
            csrf_token_hash: crypto::get_token_hash_as_hex(csrf_token.secret()),
            iat: now,
            exp: now + (timeout_minutes * 60),
            redirect_url,
        };

        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
        let state_jwt = jsonwebtoken::encode(&header, &claims, &self.context.jwt.encoding_key)?;

        Ok((auth_url, state_jwt))
    }

    pub async fn complete_google_callback(
        &self,
        code: &str,
        state: &str,
        oauth_state_cookie: &str,
    ) -> Result<(GoogleUserInfo, Option<String>), Error> {
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.validate_exp = true;
        validation.leeway = 5;

        let token_data =
            jsonwebtoken::decode::<OAuthStateClaims>(oauth_state_cookie, &self.context.jwt.decoding_key, &validation)?;

        let incoming_hash = crypto::get_token_hash_as_hex(state);
        if !constant_time_eq(&token_data.claims.csrf_token_hash, &incoming_hash) {
            logger::log_csrf_mismatch(None, &token_data.claims.csrf_token_hash, &incoming_hash);
            return Err(Error::CsrfMismatch);
        }

        let client = create_google_client(&self.context.settings.oauth)?;
        let oauth_client = oauth2::reqwest::ClientBuilder::new().build()?;

        let token_result = client
            .exchange_code(oauth2::AuthorizationCode::new(code.to_string()))
            .request_async(&oauth_client)
            .await?;

        let access_token = oauth2::TokenResponse::access_token(&token_result).secret();
        let response = self
            .context
            .http_client
            .get("https://www.googleapis.com/oauth2/v2/userinfo")
            .bearer_auth(access_token)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await?
            .error_for_status()?;

        let user_info: GoogleUserInfo = response.json().await?;

        if user_info.email.is_empty() {
            logger::log_invalid_user_info("email", &user_info.email, "google");
            return Err(Error::InvalidUserInfo);
        }

        if !user_info.verified_email {
            logger::log_invalid_user_info("verified_email", "false", "google");
            return Err(Error::UnverifiedEmail);
        }

        if user_info.id.is_empty() {
            logger::log_invalid_user_info("id", &user_info.id, "google");
            return Err(Error::InvalidUserInfo);
        }

        Ok((user_info, token_data.claims.redirect_url))
    }
}

fn validate_redirect_path(path: &str) -> Result<(), Error> {
    if path.len() > 512 {
        return Err(Error::InvalidRedirectUrl);
    }
    if !path.starts_with('/') || path.starts_with("//") || path.contains("://") {
        return Err(Error::InvalidRedirectUrl);
    }
    Ok(())
}
