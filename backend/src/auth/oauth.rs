use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    RedirectUrl, Scope, TokenUrl, TokenResponse
};
use oauth2::basic::BasicClient;
use oauth2::reqwest;
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;
use url::Url;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;

use crate::core::DbError;
use crate::core::OAuthConfig;
use crate::auth;

// 🔒 Security Notes
// OAuth tokens are temporarily passed via URL parameters (acceptable for localhost testing)
// In production, consider using secure cookies or server-side sessions
// TODO: Improve the security by implementing server-side session handling
// TODO: check if oauth without PKCE is acceptable for server-side OAuth flow
// TODO: check if any sensitive info is exposed in the logs

#[derive(Debug, Error)]
pub enum OAuthError {
    #[error("OAuth2 request failed: {0}")]
    OAuth2RequestFailed(#[from] oauth2::RequestTokenError<oauth2::HttpClientError<oauth2::reqwest::Error>, oauth2::StandardErrorResponse<oauth2::basic::BasicErrorResponseType>>),

    #[error("HTTP request failed: {0}")]
    HttpRequestFailed(#[from] reqwest::Error),

    #[error("JWT error: {0}")]
    JwtOperationFailed(#[from] auth::JwtError),

    #[error("Failed to parse redirect URI: {0}")]
    InvalidRedirectUri(#[from] url::ParseError),

    #[error("OAuth provider configuration error: {0}")]
    InvalidConfig(String),

    #[error("User info retrieval API call failed: {0}")]
    UserInfoRetrievalApiCallFailed(reqwest::Error),

    #[error("Get user from DB failed: {0}")]
    GetUserFailed(DbError),

    #[error("Insert user to DB failed: {0}")]
    InsertUserFailed(DbError),

    #[error("Insert refresh token to DB failed: {0}")]
    InsertRefreshTokenFailed(DbError),
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> axum::response::Response {
        let (status, error_message) = match self {
            OAuthError::InvalidConfig(_) => (StatusCode::INTERNAL_SERVER_ERROR, "OAuth configuration error"),
            OAuthError::UserInfoRetrievalApiCallFailed(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Failed to retrieve user information"),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, "OAuth authentication failed"),
        };

        let body = Json(json!({
            "error": error_message,
            "message": self.to_string()
        }));

        (status, body).into_response()
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
pub struct AuthRequest {
    pub code: String,
    pub state: String,
}

fn create_google_client(config: &OAuthConfig) -> Result<oauth2::Client<oauth2::StandardErrorResponse<oauth2::basic::BasicErrorResponseType>, oauth2::StandardTokenResponse<oauth2::EmptyExtraTokenFields, oauth2::basic::BasicTokenType>, oauth2::StandardTokenIntrospectionResponse<oauth2::EmptyExtraTokenFields, oauth2::basic::BasicTokenType>, oauth2::StandardRevocableToken, oauth2::StandardErrorResponse<oauth2::RevocationErrorResponseType>, oauth2::EndpointSet, oauth2::EndpointNotSet, oauth2::EndpointNotSet, oauth2::EndpointNotSet, oauth2::EndpointSet>, OAuthError> {
    if config.google_client_id.is_empty() || config.google_client_secret.is_empty() {
        return Err(OAuthError::InvalidConfig("Google OAuth not configured".to_string()));
    }
    let auth_url = AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())
        .map_err(|e| OAuthError::InvalidConfig(format!("Invalid Google auth URL: {}", e)))?;
    let token_url = TokenUrl::new("https://www.googleapis.com/oauth2/v3/token".to_string())
        .map_err(|e| OAuthError::InvalidConfig(format!("Invalid Google token URL: {}", e)))?;
    let redirect_url = RedirectUrl::new(config.google_redirect_uri.to_string())
        .map_err(|e| OAuthError::InvalidConfig(format!("Invalid Google redirect URI: {}", e)))?;
    let client = BasicClient::new(ClientId::new(config.google_client_id.to_string()))
        .set_client_secret(ClientSecret::new(config.google_client_secret.to_string()))
        .set_auth_uri(auth_url)
        .set_token_uri(token_url)
        .set_redirect_uri(redirect_url);
    Ok(client)
}

pub fn get_google_auth_url(config: &OAuthConfig) -> Result<(Url, CsrfToken), OAuthError> {
    let client = create_google_client(config)?;
    // For server-side OAuth flow, we don't need PKCE
    let (auth_url, csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .url();
    Ok((auth_url, csrf_token))
}

pub async fn get_google_user_info(config: &OAuthConfig, code: &str) -> Result<GoogleUserInfo, OAuthError> {
    let client = create_google_client(config)?;
    let http_client = oauth2::reqwest::Client::builder() // Create HTTP client for OAuth2 requests with SSRF protection
        .redirect(oauth2::reqwest::redirect::Policy::none())
        .build()?;
    let token_result = client
        .exchange_code(AuthorizationCode::new(code.to_string()))
        .request_async(&http_client)
        .await?;
    let access_token = token_result.access_token().secret();
    let user_info_url = "https://www.googleapis.com/oauth2/v2/userinfo";
    let user_info = http_client
        .get(user_info_url)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| OAuthError::UserInfoRetrievalApiCallFailed(e))?
        .json::<GoogleUserInfo>()
        .await?;
    Ok(user_info)
}
