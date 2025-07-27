use oauth2;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;
use url::Url;

use crate::core;

// 🔒 Security Notes
// OAuth tokens are temporarily passed via URL parameters (acceptable for localhost testing)
// In production, consider using secure cookies or server-side sessions
// TODO: Improve the security by implementing server-side session handling
// TODO: check if oauth without PKCE is acceptable for server-side OAuth flow
// TODO: check if any sensitive info is exposed in the logs

#[rustfmt::skip]
#[derive(Debug, Error)]
pub enum OAuthError {
    #[error("OAuth2 request failed: {0}")]
    OAuth2RequestFailed(#[from] oauth2::RequestTokenError<oauth2::HttpClientError<oauth2::reqwest::Error>, oauth2::StandardErrorResponse<oauth2::basic::BasicErrorResponseType>>),

    #[error("HTTP request failed: {0}")]
    HttpRequestFailed(#[from] oauth2::reqwest::Error),

    #[error("Failed to parse redirect URI: {0}")]
    InvalidRedirectUri(#[from] url::ParseError),

    #[error("OAuth provider configuration error: {0}")]
    InvalidConfig(String),

    #[error("User info retrieval API call failed: {0}")]
    UserInfoRetrievalApiCallFailed(reqwest::Error),
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

fn validate_google_config(config: &core::OAuthConfig) -> Result<(), OAuthError> {
    let valid = !config.google_client_id.is_empty() && !config.google_client_secret.is_empty();
    valid
        .then_some(())
        .ok_or(OAuthError::InvalidConfig("Google OAuth not configured".to_string()))
}

fn create_google_client(config: &core::OAuthConfig) -> Result<GoogleOAuth2Client, OAuthError> {
    validate_google_config(config)?;
    let redirect_url = oauth2::RedirectUrl::new(config.google_redirect_uri.clone())?;
    let auth_url = oauth2::AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string()).unwrap();
    let token_url = oauth2::TokenUrl::new("https://www.googleapis.com/oauth2/v3/token".to_string()).unwrap();
    let client = oauth2::basic::BasicClient::new(oauth2::ClientId::new(config.google_client_id.clone()))
        .set_client_secret(oauth2::ClientSecret::new(config.google_client_secret.clone()))
        .set_auth_uri(auth_url)
        .set_token_uri(token_url)
        .set_redirect_uri(redirect_url);
    Ok(client)
}

pub fn get_google_auth_url(config: &core::OAuthConfig) -> Result<(Url, oauth2::CsrfToken), OAuthError> {
    let client = create_google_client(config)?;
    // For server-side OAuth flow, we don't need PKCE
    let (auth_url, csrf_token) = client
        .authorize_url(oauth2::CsrfToken::new_random)
        .add_scope(oauth2::Scope::new("openid".to_string()))
        .add_scope(oauth2::Scope::new("email".to_string()))
        .add_scope(oauth2::Scope::new("profile".to_string()))
        .url();
    Ok((auth_url, csrf_token))
}

pub async fn get_google_user_info(context: &core::ArcContext, code: &str) -> Result<GoogleUserInfo, OAuthError> {
    let client = create_google_client(&context.config.oauth)?;
    let token_result = client
        .exchange_code(oauth2::AuthorizationCode::new(code.to_string()))
        .request_async(&context.http_client)
        .await?;
    let access_token = oauth2::TokenResponse::access_token(&token_result).secret();
    let user_info_url = "https://www.googleapis.com/oauth2/v2/userinfo";
    let user_info = context
        .http_client
        .get(user_info_url)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(OAuthError::UserInfoRetrievalApiCallFailed)?
        .json::<GoogleUserInfo>()
        .await?;
    Ok(user_info)
}
