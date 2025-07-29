use std::fs;

use axum::Json;
use axum::extract::Request;
use axum::http;
use axum::response::IntoResponse;
use chrono::Utc;
use jsonwebtoken as jwt;
use rand::TryRngCore;
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;
use uuid::Uuid;

use crate::cfg;

type TryRngError = <rand::rngs::OsRng as rand::TryRngCore>::Error;

#[rustfmt::skip]
#[derive(Debug, Error)]
pub enum JwtError {
    #[error("Failed to encode JWT token")]
    EncodingFailed(jwt::errors::Error),

    #[error("Failed to decode JWT token")]
    DecodingFailed(jwt::errors::Error),

    #[error("File system operation failed")]
    FileSystemOperationFailed { #[from] source: std::io::Error },

    #[error("Random number generation operation failed")]
    RngOperationFailed { source: TryRngError },

    #[error("Token has expired")]
    TokenExpired,

    #[error("Invalid token")]
    InvalidToken,

    #[error("Invalid authorization header")]
    InvalidAuthorizationHeader,
}

impl IntoResponse for JwtError {
    fn into_response(self) -> axum::response::Response {
        tracing::error!(
            error_type = %std::any::type_name::<Self>(),
            error_subtype = %std::any::type_name_of_val(&self),
            error_message = %self);

        #[rustfmt::skip]
        #[allow(clippy::match_same_arms)]
        let (status, error_message) = match self {
            Self::RngOperationFailed { source: _ } => (http::StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            Self::FileSystemOperationFailed { source: _ } => (http::StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            Self::EncodingFailed(_) => (http::StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            Self::DecodingFailed(_) => (http::StatusCode::UNAUTHORIZED, "Invalid or missing authentication token".to_string()),
            Self::TokenExpired => (http::StatusCode::UNAUTHORIZED, "Authentication token has expired".to_string()),
            Self::InvalidToken => (http::StatusCode::UNAUTHORIZED, "Invalid authentication token".to_string()),
            Self::InvalidAuthorizationHeader => (http::StatusCode::UNAUTHORIZED, "Invalid or missing authorization header".to_string()),
        };

        let body = Json(json!({
            "result": "error",
            "message": error_message
        }));

        (status, body).into_response()
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TokenType {
    Access,
    Refresh,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AccessTokenClaims {
    pub sub: String,            // Subject (user ID)
    pub username: String,       // Username for convenience
    pub tenant_id: Option<i64>, // Tenant ID if applicable
    pub exp: i64,               // Expiration time
    pub iat: i64,               // Issued at
    pub jti: String,            // JWT ID (unique identifier)
    pub token_type: TokenType,  // "access"
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RefreshTokenClaims {
    pub sub: String,           // Subject (user ID)
    pub exp: i64,              // Expiration time
    pub iat: i64,              // Issued at
    pub jti: String,           // JWT ID (unique identifier)
    pub token_type: TokenType, // "refresh"
}

/// Response structure for token endpoints
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub access_token_expires_in: i64,  // Seconds until access token expires
    pub refresh_token_expires_in: i64, // Seconds until refresh token expires
}

impl TokenResponse {
    #[must_use]
    pub const fn new(ctx: &JwtContext, access_token: String, refresh_token: String) -> Self {
        Self {
            access_token,
            refresh_token,
            access_token_expires_in: ctx.access_token_expiry,
            refresh_token_expires_in: ctx.refresh_token_expiry,
        }
    }
}

#[derive(Clone)]
pub struct JwtContext {
    pub encoding_key: jwt::EncodingKey,
    pub decoding_key: jwt::DecodingKey,
    pub validation: jwt::Validation,
    pub access_token_expiry: i64,
    pub refresh_token_expiry: i64,
}

impl JwtContext {
    pub fn new(settings: &cfg::JwtSettings, secret: &str) -> Result<Self, JwtError> {
        let encoding_key = jwt::EncodingKey::from_secret(secret.as_ref());
        let decoding_key = jwt::DecodingKey::from_secret(secret.as_ref());
        let mut validation = jwt::Validation::new(jwt::Algorithm::HS256);
        validation.leeway = 0;

        Ok(Self {
            encoding_key,
            decoding_key,
            validation,
            access_token_expiry: settings.access_token_expiry,
            refresh_token_expiry: settings.refresh_token_expiry,
        })
    }
}

/// Generate a new access token
pub fn generate_access_token(
    ctx: &JwtContext,
    user_id: i64,
    user_name: &str,
    tenant_id: Option<i64>,
) -> Result<String, JwtError> {
    let now = Utc::now().timestamp();
    let header = jwt::Header::new(jwt::Algorithm::HS256);
    let claims = AccessTokenClaims {
        sub: user_id.to_string(),
        username: user_name.to_string(),
        tenant_id,
        exp: now + ctx.access_token_expiry,
        iat: now,
        jti: Uuid::new_v4().to_string(),
        token_type: TokenType::Access,
    };
    jwt::encode(&header, &claims, &ctx.encoding_key).map_err(JwtError::EncodingFailed)
}

/// Generate a new refresh token
pub fn generate_refresh_token(ctx: &JwtContext, user_id: i64) -> Result<String, JwtError> {
    let now = Utc::now().timestamp();
    let header = jwt::Header::new(jwt::Algorithm::HS256);
    let claims = RefreshTokenClaims {
        sub: user_id.to_string(),
        exp: now + ctx.refresh_token_expiry,
        iat: now,
        jti: Uuid::new_v4().to_string(),
        token_type: TokenType::Refresh,
    };
    jwt::encode(&header, &claims, &ctx.encoding_key).map_err(JwtError::EncodingFailed)
}

pub fn decode_access_token_from_req(ctx: &JwtContext, req: &Request) -> Result<AccessTokenClaims, JwtError> {
    // Extract the Authorization header
    let auth_header = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .ok_or(JwtError::InvalidAuthorizationHeader)?;

    // Extract Bearer token
    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or(JwtError::InvalidAuthorizationHeader)?;

    // Decode the access token
    decode_access_token(ctx, token)
}

/// Validate and decode an access token
pub fn decode_access_token(ctx: &JwtContext, token: &str) -> Result<AccessTokenClaims, JwtError> {
    let token_data = jwt::decode::<AccessTokenClaims>(token, &ctx.decoding_key, &ctx.validation)?;
    let valid = token_data.claims.token_type == TokenType::Access;
    valid.then_some(token_data.claims).ok_or(JwtError::InvalidToken)
}

/// Validate and decode a refresh token
pub fn decode_refresh_token(ctx: &JwtContext, token: &str) -> Result<RefreshTokenClaims, JwtError> {
    let token_data = jwt::decode::<RefreshTokenClaims>(token, &ctx.decoding_key, &ctx.validation)?;
    let valid = token_data.claims.token_type == TokenType::Refresh;
    valid.then_some(token_data.claims).ok_or(JwtError::InvalidToken)
}

/// Loads or creates a JWT secret
pub fn get_jwt_secret() -> Result<String, JwtError> {
    // check persisted secret file
    let secret_file_path = cfg::AppSettings::get_config_path().join(".jwt_secret");
    if let Ok(file_secret) = fs::read_to_string(&secret_file_path) {
        let trimmed_secret = file_secret.trim();
        if !trimmed_secret.is_empty() && trimmed_secret.len() >= 32 {
            return Ok(trimmed_secret.to_string());
        }
    }

    // Create config directory if it doesn't exist
    if let Some(parent) = &secret_file_path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Write the secret to file with restricted permissions
    let new_secret = generate_secure_secret()?;
    fs::write(&secret_file_path, &new_secret)?;

    // Set file permissions to be readable only by owner (Unix-like systems)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&secret_file_path)?.permissions();
        perms.set_mode(0o600); // rw-------
        fs::set_permissions(&secret_file_path, perms)?;
    }

    tracing::info!("Generated new JWT secret in {}", secret_file_path.to_string_lossy());
    Ok(new_secret)
}

/// Generates a cryptographically secure random secret
fn generate_secure_secret() -> Result<String, JwtError> {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|e| JwtError::RngOperationFailed { source: e })?;
    Ok(hex::encode(bytes))
}

/// Maps jsonwebtoken errors to our custom `JwtError` type
#[allow(clippy::match_same_arms)]
impl From<jwt::errors::Error> for JwtError {
    fn from(e: jwt::errors::Error) -> Self {
        match e.kind() {
            jwt::errors::ErrorKind::ExpiredSignature => Self::TokenExpired,
            jwt::errors::ErrorKind::InvalidToken => Self::InvalidToken,
            jwt::errors::ErrorKind::Json(_) => Self::InvalidToken,
            _ => Self::DecodingFailed(e),
        }
    }
}
