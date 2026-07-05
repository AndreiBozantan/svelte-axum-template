use chrono::Utc;
use jsonwebtoken;
use oauth2;
use percent_encoding;
use serde::Deserialize;
use serde::Serialize;
use tracing::error;
use tracing::info;
use tracing::warn;
use url::Url;

use crate::platform::common;
use crate::platform::config;
use crate::platform::crypto;

use crate::platform::identity::auth;

#[derive(Debug, thiserror::Error)]
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

/// Claims stored within the `oauth_state` cookie.
///
/// NOTE: These claims are signed with HS256 to ensure integrity and prevent tampering,
/// but they are not encrypted (no JWE). This is a deliberate, standard choice, not an
/// oversight:
///
/// 1. The JWT lives in an `HttpOnly; Secure; SameSite=Lax` cookie scoped to the OAuth
///    callback path. It is never placed in a URL, so it's never exposed via Referer
///    headers, browser history, or server access logs of other routes. `HttpOnly` also
///    blocks JS/XSS access to its contents.
/// 2. The PKCE verifier and CSRF hash are only meant to be confidential from parties
///    outside this single login flow (e.g., other websites, network attackers without
///    the cookie). The user's own browser is already inside that trust boundary — it's
///    the party performing the login — so it seeing its own verifier is not a privilege
///    escalation.
/// 3. If the cookie itself is exfiltrated (e.g. XSS bypass, compromised proxy, log
///    misconfiguration), the attacker can already replay/use the full authenticated
///    value. Encrypting individual fields wouldn't prevent that — it only hides field
///    contents, not usability of the token — so JWE adds no meaningful defense here.
/// 4. Short `exp` (bound to `session_timeout_minutes`) and Google's single-use
///    authorization codes bound the replay window independent of encryption.
///
/// Signature verification (HS256) is therefore sufficient to bind these claims to the
/// browser that initiated the flow; this matches standard practice in OAuth state-cookie
/// implementations (e.g. oauth2-proxy, Auth.js).
#[derive(Debug, Serialize, Deserialize)]
pub struct OAuthStateClaims {
    pub csrf_token_hash: String,
    pub pkce_verifier: String,
    pub redirect_url: String,
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
        error!(
            value = %config.google_redirect_uri,
            provider = "google",
            "invalid_redirect_uri"
        );
        return Err(Error::InvalidConfig(
            "Google Redirect URI must use HTTPS in non-localhost environments".to_string(),
        ));
    }

    Ok(())
}

pub fn check_oauth_config(config: &config::OAuthSettings) {
    if let Err(error) = validate_google_config(config) {
        warn!(error = error.to_string(), provider = "google", "incomplete_config");
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
pub struct Service {
    pub context: common::ArcContext,
    pub auth: auth::Service,
}

impl Service {
    #[must_use]
    pub const fn new(
        context: common::ArcContext,
        auth_service: auth::Service,
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
        let redirect_url = match redirect_url {
            Some(url) if validate_redirect_path(&url).is_ok() => url,
            _ => "/".to_string(),
        };

        let client = create_google_client(&self.context.settings.oauth)?;
        let (pkce_challenge, pkce_verifier) = oauth2::PkceCodeChallenge::new_random_sha256();
        let (mut auth_url, csrf_token) = client
            .authorize_url(oauth2::CsrfToken::new_random)
            .set_pkce_challenge(pkce_challenge)
            .add_scope(oauth2::Scope::new("openid".to_string()))
            .add_scope(oauth2::Scope::new("email".to_string()))
            .add_scope(oauth2::Scope::new("profile".to_string()))
            .url();
        auth_url.query_pairs_mut().append_pair("prompt", "select_account");

        let now = Utc::now().timestamp();
        let timeout_minutes = i64::from(self.context.settings.oauth.session_timeout_minutes);
        let claims = OAuthStateClaims {
            csrf_token_hash: crypto::get_hash_as_hex(csrf_token.secret()),
            pkce_verifier: pkce_verifier.secret().clone(),
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
    ) -> Result<(GoogleUserInfo, String), Error> {
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.validate_exp = true;
        validation.leeway = 5;

        let token_data =
            jsonwebtoken::decode::<OAuthStateClaims>(oauth_state_cookie, &self.context.jwt.decoding_key, &validation)?;

        let incoming_hash = crypto::get_hash_as_hex(state);
        if !crypto::constant_time_eq(&token_data.claims.csrf_token_hash, &incoming_hash) {
            info!(
                expected_hash = %token_data.claims.csrf_token_hash,
                actual_hash = %incoming_hash,
                "csrf_token_mismatch"
            );
            return Err(Error::CsrfMismatch);
        }

        let client = create_google_client(&self.context.settings.oauth)?;
        let oauth_client = oauth2::reqwest::ClientBuilder::new()
            .timeout(std::time::Duration::from_secs(10))
            .build()?;

        let pkce_verifier = oauth2::PkceCodeVerifier::new(token_data.claims.pkce_verifier);

        let token_result = client
            .exchange_code(oauth2::AuthorizationCode::new(code.to_string()))
            .set_pkce_verifier(pkce_verifier)
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
            warn!(provider = "google", "empty_email");
            return Err(Error::InvalidUserInfo);
        }

        if !user_info.verified_email {
            warn!(
                provider = "google",
                email_hash = %crypto::get_hash_as_hex(&user_info.email),
                "unverified_email"
            );
            return Err(Error::UnverifiedEmail);
        }

        if user_info.id.is_empty() {
            warn!(
                provider = "google",
                email_hash = %crypto::get_hash_as_hex(&user_info.email),
                "empty_user_id"
            );
            return Err(Error::InvalidUserInfo);
        }

        validate_redirect_path(&token_data.claims.redirect_url)?;

        Ok((user_info, token_data.claims.redirect_url))
    }
}

pub fn validate_redirect_path(path: &str) -> Result<(), Error> {
    if path.len() > 256 {
        return Err(Error::InvalidRedirectUrl);
    }
    // Must start with exactly one slash, not two
    if !path.starts_with('/') || path.starts_with("//") {
        return Err(Error::InvalidRedirectUrl);
    }
    // Reject protocol-relative and absolute URLs after percent-decoding
    let decoded = percent_encoding::percent_decode_str(path)
        .decode_utf8()
        .map_err(|_| Error::InvalidRedirectUrl)?;

    // Enforce idempotent decoding to prevent double percent-encoding bypasses
    let double_decoded = percent_encoding::percent_decode_str(&decoded)
        .decode_utf8()
        .map_err(|_| Error::InvalidRedirectUrl)?;
    if decoded != double_decoded {
        return Err(Error::InvalidRedirectUrl);
    }

    if decoded.chars().any(char::is_control)
        || decoded.contains("://")
        || decoded.contains('\\')
        || decoded.starts_with("//")
    {
        return Err(Error::InvalidRedirectUrl);
    }
    Ok(())
}
