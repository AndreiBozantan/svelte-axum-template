use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    RedirectUrl, Scope, TokenUrl,
};
use oauth2::basic::BasicClient;
use oauth2::reqwest::async_http_client;
use reqwest::Client;
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
// TODO: upgrade to oauth2 v5

#[derive(Debug, Error)]
pub enum OAuthError {
    #[error("OAuth2 request failed: {0}")]
    OAuth2RequestFailed(#[from] oauth2::RequestTokenError<oauth2::reqwest::Error<reqwest::Error>, oauth2::StandardErrorResponse<oauth2::basic::BasicErrorResponseType>>),

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

/// OAuth2 service for handling various OAuth providers
pub struct OAuthService {
    google_client: Option<BasicClient>,
    http_client: Client,
}

impl OAuthService {
    pub fn new(config: &OAuthConfig) -> Result<Self, OAuthError> {
        if config.google_client_id.is_empty() || config.google_client_secret.is_empty() {
            return Ok(Self {google_client: None, http_client: Client::new()});
        }
        let client_id = ClientId::new(config.google_client_id.clone());
        let client_secret = ClientSecret::new(config.google_client_secret.clone());
        let auth_url = AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())
            .map_err(|e| OAuthError::InvalidConfig(format!("Invalid Google auth URL: {}", e)))?;
        let token_url = TokenUrl::new("https://www.googleapis.com/oauth2/v3/token".to_string())
            .map_err(|e| OAuthError::InvalidConfig(format!("Invalid Google token URL: {}", e)))?;
        let google_client = BasicClient::new(client_id, Some(client_secret), auth_url, Some(token_url))
            .set_redirect_uri(RedirectUrl::new(config.google_redirect_uri.clone())?);
        Ok(Self {google_client: Some(google_client), http_client: Client::new()})
    }

    pub fn get_google_auth_url(&self) -> Result<(Url, CsrfToken), OAuthError> {
        let client = self.google_client.as_ref()
            .ok_or_else(|| OAuthError::InvalidConfig("Google OAuth not configured".to_string()))?;
        // For server-side OAuth flow, we don't need PKCE
        let (auth_url, csrf_token) = client
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new("openid".to_string()))
            .add_scope(Scope::new("email".to_string()))
            .add_scope(Scope::new("profile".to_string()))
            .url();
        Ok((auth_url, csrf_token))
    }

    pub async fn exchange_google_code(&self, code: &str) -> Result<oauth2::StandardTokenResponse<oauth2::EmptyExtraTokenFields, oauth2::basic::BasicTokenType>, OAuthError> {
        let client = self.google_client.as_ref()
            .ok_or_else(|| OAuthError::InvalidConfig("Google OAuth not configured".to_string()))?;
        client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .request_async(async_http_client)
            .await
            .map_err(OAuthError::OAuth2RequestFailed)
    }

    pub async fn get_google_user_info(&self, access_token: &str) -> Result<GoogleUserInfo, OAuthError> {
        let user_info_url = "https://www.googleapis.com/oauth2/v2/userinfo";
        let user_info = self.http_client
            .get(user_info_url)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| OAuthError::UserInfoRetrievalApiCallFailed(e))?
            .json()
            .await?;
        Ok(user_info)
    }
}
