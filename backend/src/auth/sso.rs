use chrono::Utc;
use jsonwebtoken;
use oauth2;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;
use url::Url;

use crate::auth;
use crate::cfg;
use crate::core;

#[rustfmt::skip]
#[derive(Debug, Error)]
pub enum SsoError {
    #[error("OAuth2 request failed: {0}")]
    OAuth2RequestFailed(#[from] oauth2::RequestTokenError<oauth2::HttpClientError<oauth2::reqwest::Error>, oauth2::StandardErrorResponse<oauth2::basic::BasicErrorResponseType>>),

    #[error("OAuth provider configuration error: {0}")]
    InvalidConfig(String),

    #[error("User info retrieval API call failed: {0}")]
    UserInfoRetrievalApiCallFailed(reqwest::Error),

    #[error("CSRF token validation failed")]
    CsrfValidationFailed,

    #[error("OAuth session expired or invalid")]
    SessionExpired,

    #[error("Invalid redirect URL")]
    InvalidRedirectUrl,

    #[error("User info returned by provider was invalid")]
    InvalidUserInfo,
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
pub struct AuthRequest {
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

// Type alias to simplify the function signature
type GoogleOAuth2Client = oauth2::Client<
    oauth2::StandardErrorResponse<oauth2::basic::BasicErrorResponseType>,
    oauth2::StandardTokenResponse<oauth2::EmptyExtraTokenFields, oauth2::basic::BasicTokenType>,
    oauth2::StandardTokenIntrospectionResponse<oauth2::EmptyExtraTokenFields, oauth2::basic::BasicTokenType>,
    oauth2::StandardRevocableToken,
    oauth2::StandardErrorResponse<oauth2::RevocationErrorResponseType>,
    oauth2::EndpointSet,    // HasAuthUrl
    oauth2::EndpointNotSet, // HasDeviceAuthUrl
    oauth2::EndpointNotSet, // HasIntrospectionUrl
    oauth2::EndpointNotSet, // HasRevocationUrl
    oauth2::EndpointSet,    // HasTokenUrl
>;

/// Constant-time string equality to prevent timing-based CSRF oracle attacks.
/// This is always processing all the bytes regardless of where the first difference is.
/// Both inputs must be equal-length hex digests.
fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn validate_google_config(config: &cfg::OAuthSettings) -> Result<(), SsoError> {
    if config.google_client_id.is_empty() {
        return Err(SsoError::InvalidConfig(
            "Google Client ID is not configured".to_string(),
        ));
    }
    if config.google_client_secret.is_empty() {
        return Err(SsoError::InvalidConfig(
            "Google Client Secret is not configured".to_string(),
        ));
    }
    if config.google_redirect_uri.is_empty() {
        return Err(SsoError::InvalidConfig(
            "Google Redirect URI is not configured".to_string(),
        ));
    }

    // validate redirect URI format
    let parsed: Url = config
        .google_redirect_uri
        .parse()
        .map_err(|_| SsoError::InvalidConfig("Invalid Google Redirect URI format".to_string()))?;

    // use exact localhost check to avoid matching attacker-controlled domains like `notlocalhost.evil.com`
    let host = parsed.host_str().unwrap_or("");
    let is_localhost = host == "localhost" || host == "127.0.0.1" || host == "::1";
    if parsed.scheme() != "https" && !is_localhost {
        // in production, ensure HTTPS is used for the redirect URI
        auth::log_invalid_config("oauth.google_redirect_uri", &config.google_redirect_uri);
        return Err(SsoError::InvalidConfig(
            "Google Redirect URI must use HTTPS in non-localhost environments".to_string(),
        ));
    }

    Ok(())
}

fn create_google_client(config: &cfg::OAuthSettings) -> Result<GoogleOAuth2Client, SsoError> {
    validate_google_config(config)?;
    let redirect_url = oauth2::RedirectUrl::new(config.google_redirect_uri.clone())
        .map_err(|_| SsoError::InvalidConfig("Invalid Google Redirect URI format".to_string()))?;
    let auth_url = oauth2::AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())
        .map_err(|_| SsoError::InvalidConfig("Invalid Google auth URL".to_string()))?;
    let token_url = oauth2::TokenUrl::new("https://www.googleapis.com/oauth2/v3/token".to_string())
        .map_err(|_| SsoError::InvalidConfig("Invalid Google token URL".to_string()))?;

    let client = oauth2::basic::BasicClient::new(oauth2::ClientId::new(config.google_client_id.clone()))
        .set_client_secret(oauth2::ClientSecret::new(config.google_client_secret.clone()))
        .set_auth_uri(auth_url)
        .set_token_uri(token_url)
        .set_redirect_uri(redirect_url);
    Ok(client)
}

pub async fn get_google_auth_url_and_csrf_token(
    context: &core::ArcContext,
    redirect_url: Option<String>,
) -> Result<(Url, String), SsoError> {
    // validate redirect URL if provided
    if let Some(url) = &redirect_url {
        validate_redirect_url(url, &context.settings.oauth)?;
    }

    // generate CSRF token and create OAuth session
    let client = create_google_client(&context.settings.oauth)?;
    let (auth_url, csrf_token) = client
        .authorize_url(oauth2::CsrfToken::new_random)
        .add_scope(oauth2::Scope::new("openid".to_string()))
        .add_scope(oauth2::Scope::new("email".to_string()))
        .add_scope(oauth2::Scope::new("profile".to_string()))
        .url();

    let now = Utc::now().timestamp();
    let timeout_minutes = context.settings.oauth.session_timeout_minutes as i64;
    let claims = OAuthStateClaims {
        csrf_token_hash: auth::get_token_hash_as_hex(csrf_token.secret()),
        redirect_url: redirect_url,
        iat: now,
        exp: now + (timeout_minutes * 60),
    };

    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    let state_jwt = jsonwebtoken::encode(&header, &claims, &context.jwt.encoding_key).map_err(|e| {
        auth::log_internal_error(&e, "encode_oauth_state");
        SsoError::InvalidConfig("Failed to encode OAuth state JWT".to_string())
    })?;

    Ok((auth_url, state_jwt))
}

pub async fn get_google_user_info(
    context: &core::ArcContext,
    code: &str,
    state: &str,
    oauth_state_cookie: &str,
) -> Result<(GoogleUserInfo, Option<String>), SsoError> {
    // decode and validate JWT cookie
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.validate_exp = true; // explicitly enforce expiry — do not rely on library default
    validation.leeway = 5; // small leeway for clock skew tolerance across distributed instances

    let token_data =
        jsonwebtoken::decode::<OAuthStateClaims>(oauth_state_cookie, &context.jwt.decoding_key, &validation).map_err(
            |e| {
                auth::log_internal_error(&e, "decode_oauth_state");
                match e.kind() {
                    jsonwebtoken::errors::ErrorKind::ExpiredSignature => SsoError::SessionExpired,
                    _ => SsoError::CsrfValidationFailed,
                }
            },
        )?;

    // hash the incoming `state` parameter and compare hashes with constant-time
    // equality to prevent timing-based oracle attacks on the CSRF token
    let incoming_hash = auth::get_token_hash_as_hex(state);
    if !constant_time_eq(&token_data.claims.csrf_token_hash, &incoming_hash) {
        auth::log_csrf_mismatch(None, &token_data.claims.csrf_token_hash, &incoming_hash);
        return Err(SsoError::CsrfValidationFailed);
    }

    let client = create_google_client(&context.settings.oauth)?;

    // exchange authorization code for tokens
    let oauth_client = oauth2::reqwest::ClientBuilder::new()
        .build()
        .map_err(|e| {
            auth::log_internal_error(&e, "create_oauth_client");
            SsoError::OAuth2RequestFailed(oauth2::RequestTokenError::Other(format!("Failed to create HTTP client: {e}")))
        })?;

    let token_result = client
        .exchange_code(oauth2::AuthorizationCode::new(code.to_string()))
        .request_async(&oauth_client)
        .await
        .map_err(|e| {
            auth::log_internal_error(&e, "oauth_exchange_code");
            SsoError::OAuth2RequestFailed(e)
        })?;

    // CAUTION: access_token must never appear in logs, error messages, or any other human-readable output.
    let access_token = oauth2::TokenResponse::access_token(&token_result).secret();

    // fetch user info from Google
    let user_info_url = "https://www.googleapis.com/oauth2/v2/userinfo";
    let response = context
        .http_client
        .get(user_info_url)
        .bearer_auth(access_token)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(SsoError::UserInfoRetrievalApiCallFailed)?;

    if !response.status().is_success() {
        auth::log_provider_api_error(response.status(), "google");
        return Err(SsoError::InvalidConfig("OAuth provider returned an error".to_string()));
    }

    let user_info: GoogleUserInfo = response
        .json()
        .await
        .map_err(SsoError::UserInfoRetrievalApiCallFailed)?;

    if user_info.email.is_empty() {
        auth::log_invalid_user_info("email", &user_info.email, "google");
        return Err(SsoError::InvalidUserInfo);
    }

    if !user_info.verified_email {
        auth::log_invalid_user_info("verified_email", "false", "google");
        return Err(SsoError::InvalidUserInfo);
    }

    if user_info.id.is_empty() {
        auth::log_invalid_user_info("id", &user_info.id, "google");
        return Err(SsoError::InvalidUserInfo);
    }

    Ok((user_info, token_data.claims.redirect_url))
}

/// Validate a redirect URL to prevent open redirect attacks.
/// Validation happens at JWT-creation time so the signed token acts as a
/// tamper-evident record - no re-validation is needed at callback time.
fn validate_redirect_url(url: &str, config: &cfg::OAuthSettings) -> Result<(), SsoError> {
    let parsed_url: Url = url.parse().map_err(|_| SsoError::InvalidRedirectUrl)?;

    // explicit scheme allowlist instead of implicit denylist - rejects
    // javascript:, data:, ftp: and any other unexpected schemes up front
    let scheme = parsed_url.scheme();
    if scheme != "https" && scheme != "http" {
        auth::log_redirect_violation("invalid_scheme", url);
        return Err(SsoError::InvalidRedirectUrl);
    }

    // check against allowed domains from configuration
    match parsed_url.host_str() {
        None => return Err(SsoError::InvalidRedirectUrl),
        Some(host) => {
            let is_allowed = config
                .allowed_redirect_domains
                .iter()
                .any(|allowed| host == allowed || host.ends_with(&format!(".{}", allowed)));

            if !is_allowed {
                auth::log_redirect_violation("unauthorized_host", host);
                return Err(SsoError::InvalidRedirectUrl);
            }

            // exact localhost check, avoid matching attacker-controlled hosts like `notlocalhost.evil.com`
            let is_localhost = host == "localhost" || host == "127.0.0.1" || host == "::1";
            if scheme != "https" && !is_localhost {
                auth::log_redirect_violation("non_https_redirect", url);
                return Err(SsoError::InvalidRedirectUrl);
            }
        }
    }

    Ok(())
}
