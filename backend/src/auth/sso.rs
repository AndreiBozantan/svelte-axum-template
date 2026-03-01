use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use oauth2;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;
use tokio::sync::RwLock;
use url::Url;

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

    #[error("OAuth session expired: age {age_minutes} minutes")]
    SessionNotFound { age_minutes: i64 },

    #[error("Invalid redirect URL")]
    InvalidRedirectUrl,
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

#[derive(Debug, Clone)]
pub struct OAuthSessionEntry {
    pub csrf_token: String,
    pub redirect_url: Option<String>,
    pub created_at: DateTime<Utc>,
}

// In-memory store for OAuth sessions (in production, use Redis or database)
pub type OAuthSessionStore = Arc<RwLock<HashMap<String, OAuthSessionEntry>>>;

pub fn create_oauth_session_store() -> OAuthSessionStore {
    Arc::new(RwLock::new(HashMap::new()))
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
    let _: Url = config
        .google_redirect_uri
        .parse()
        .map_err(|_| SsoError::InvalidConfig("Invalid Google Redirect URI format".to_string()))?;

    // in production, ensure HTTPS
    if !config.google_redirect_uri.starts_with("https://") && !config.google_redirect_uri.contains("localhost") {
        tracing::warn!(
            "Google OAuth redirect URI should use HTTPS in production: {}",
            config.google_redirect_uri
        );
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

pub async fn get_google_auth_url(
    context: &core::ArcContext,
    redirect_url: Option<&String>,
) -> Result<(Url, String), SsoError> {
    // validate redirect URL if provided
    if let Some(ref url) = redirect_url {
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

    // store session_entry with cleanup of expired entries
    let state = csrf_token.secret().clone();
    store_session_entry(context, redirect_url.cloned(), state.clone()).await;

    Ok((auth_url, state))
}

pub async fn get_google_user_info(
    context: &core::ArcContext,
    code: &str,
    state: &str,
) -> Result<(GoogleUserInfo, Option<String>), SsoError> {
    // validate state parameter (CSRF protection)
    let session_entry = {
        let mut store = context.oauth_session_store.write().await;
        store.remove(state).ok_or(SsoError::CsrfValidationFailed)?
    };

    if session_entry.csrf_token != state {
        tracing::warn!(
            "CSRF token mismatch: expected {}, got {}",
            session_entry.csrf_token,
            state
        );
        return Err(SsoError::CsrfValidationFailed);
    }

    // check session_entry age (configurable timeout)
    let timeout_minutes = Duration::minutes(context.settings.oauth.session_timeout_minutes as i64);
    let session_entry_age = Utc::now() - session_entry.created_at;
    if session_entry_age > timeout_minutes {
        return Err(SsoError::SessionNotFound {
            age_minutes: session_entry_age.num_minutes(),
        });
    }

    let client = create_google_client(&context.settings.oauth)?;

    // exchange authorization code for tokens
    let token_result = client
        .exchange_code(oauth2::AuthorizationCode::new(code.to_string()))
        .request_async(&context.http_client)
        .await
        .map_err(|e| {
            tracing::error!("Failed to exchange authorization code: {}", e);
            SsoError::OAuth2RequestFailed(e)
        })?;

    let access_token = oauth2::TokenResponse::access_token(&token_result).secret();

    // fetch user info from Google
    let user_info_url = "https://www.googleapis.com/oauth2/v2/userinfo";
    let response = context
        .http_client
        .get(user_info_url)
        .bearer_auth(access_token)
        .timeout(std::time::Duration::from_secs(10)) // Add timeout
        .send()
        .await
        .map_err(SsoError::UserInfoRetrievalApiCallFailed)?;

    if !response.status().is_success() {
        tracing::error!("Google userinfo API returned status: {}", response.status());
        return Err(SsoError::InvalidConfig(
            "Google userinfo API returned error".to_string(),
        ));
    }

    let user_info: GoogleUserInfo = response
        .json()
        .await
        .map_err(SsoError::UserInfoRetrievalApiCallFailed)?;

    // validate user info
    if user_info.email.is_empty() || user_info.id.is_empty() {
        tracing::error!("Invalid user info received from Google: missing email or ID");
        return Err(SsoError::InvalidConfig("Invalid user info from Google".to_string()));
    }

    tracing::info!(
        "Successfully retrieved user info for: {} ({})",
        user_info.name,
        user_info.email
    );

    Ok((user_info, session_entry.redirect_url))
}

async fn store_session_entry(context: &core::ArcContext, redirect_url: Option<String>, state: String) {
    // store session_entry with cleanup of expired entries
    let mut session_store = context.oauth_session_store.write().await;
    let session_entry = OAuthSessionEntry {
        csrf_token: state.clone(),
        redirect_url: redirect_url,
        created_at: Utc::now(),
    };

    // clean up expired sessions (configurable timeout)
    let timeout_minutes = Duration::minutes(context.settings.oauth.session_timeout_minutes as i64);
    let cutoff = Utc::now() - timeout_minutes;
    session_store.retain(|_, entry| entry.created_at > cutoff);

    // store new session
    session_store.insert(state, session_entry);
}

/// validate redirect URL to prevent open redirect attacks
fn validate_redirect_url(url: &str, config: &cfg::OAuthSettings) -> Result<(), SsoError> {
    let parsed_url: Url = url.parse().map_err(|_| SsoError::InvalidRedirectUrl)?;

    // check against allowed domains from configuration
    match parsed_url.host_str() {
        Some(host) => {
            let is_allowed = config
                .allowed_redirect_domains
                .iter()
                .any(|allowed| host == allowed || host.ends_with(&format!(".{}", allowed)));

            if !is_allowed {
                tracing::warn!("Rejected redirect to unauthorized host: {}", host);
                return Err(SsoError::InvalidRedirectUrl);
            }
        }
        None => return Err(SsoError::InvalidRedirectUrl),
    }

    // ensure HTTPS in production (except localhost)
    if parsed_url.scheme() != "https" && !parsed_url.host_str().unwrap_or("").contains("localhost") {
        tracing::warn!("Rejected non-HTTPS redirect URL in production: {}", url);
        return Err(SsoError::InvalidRedirectUrl);
    }

    Ok(())
}
