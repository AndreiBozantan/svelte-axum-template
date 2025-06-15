use axum::http;
use axum::extract::Request;
use chrono::Utc;
use jsonwebtoken as jwt;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use thiserror::Error;

use crate::appconfig::JwtConfig;

#[derive(Debug, Error)]
pub enum JwtError {
    #[error("Failed to encode JWT token")]
    EncodingError(#[from] jsonwebtoken::errors::Error),

    #[error("Failed to decode JWT token")]
    DecodingError,

    #[error("Token has expired")]
    TokenExpired,

    #[error("Invalid token")]
    InvalidToken,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AccessTokenClaims {
    pub sub: String,        // Subject (user ID)
    pub username: String,   // Username for convenience
    pub tenant_id: Option<i64>, // Tenant ID if applicable
    pub exp: i64,          // Expiration time
    pub iat: i64,          // Issued at
    pub jti: String,       // JWT ID (unique identifier)
    pub token_type: String, // "access"
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RefreshTokenClaims {
    pub sub: String,        // Subject (user ID)
    pub exp: i64,          // Expiration time
    pub iat: i64,          // Issued at
    pub jti: String,       // JWT ID (unique identifier)
    pub token_type: String, // "refresh"
}

/// Response structure for token endpoints
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64, // Seconds until access token expires
    pub refresh_expires_in: i64, // Seconds until refresh token expires
}

impl TokenResponse {
    pub fn new(
        access_token: String,
        refresh_token: String,
        access_expires_in: i64,
        refresh_expires_in: i64,
    ) -> Self {
        Self {
            access_token,
            refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: access_expires_in,
            refresh_expires_in,
        }
    }
}

/// Generate a new access token
pub fn generate_access_token(config: &JwtConfig, user_id: i64, user_name: &str, tenant_id: Option<i64>) -> Result<String, JwtError> {
    let now = Utc::now().timestamp();
    let header = jwt::Header::new(jwt::Algorithm::HS256);
    let encoding_key = jwt::EncodingKey::from_secret(config.secret.as_ref());
    let claims = AccessTokenClaims {
        sub: user_id.to_string(),
        username: user_name.to_string(),
        tenant_id,
        exp: now + config.access_token_expiry,
        iat: now,
        jti: Uuid::new_v4().to_string(),
        token_type: "access".to_string(),
    };
    jwt::encode(&header, &claims, &encoding_key).map_err(JwtError::EncodingError)
}

/// Generate a new refresh token
pub fn generate_refresh_token(config: &JwtConfig, user_id: i64) -> Result<String, JwtError> {
    let now = Utc::now().timestamp();
    let header = jwt::Header::new(jwt::Algorithm::HS256);
    let encoding_key = jwt::EncodingKey::from_secret(config.secret.as_ref());
    let claims = RefreshTokenClaims {
        sub: user_id.to_string(),
        exp: now + config.refresh_token_expiry,
        iat: now,
        jti: Uuid::new_v4().to_string(),
        token_type: "refresh".to_string(),
    };
    jwt::encode(&header, &claims, &encoding_key).map_err(JwtError::EncodingError)
}

pub fn decode_access_token_from_req(config: &JwtConfig, req: &Request) -> Result<AccessTokenClaims, JwtError> {
    // Extract the Authorization header
    let auth_header = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .ok_or(JwtError::DecodingError)?;

    // Extract Bearer token
    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or(JwtError::DecodingError)?;

    // Decode the access token
    decode_access_token(config, token)
}

/// Validate and decode an access token
pub fn decode_access_token(config: &JwtConfig, token: &str) -> Result<AccessTokenClaims, JwtError> {
    let decoding_key = jwt::DecodingKey::from_secret(config.secret.as_ref());
    let validation = jwt::Validation::new(jwt::Algorithm::HS256);

    match jwt::decode::<AccessTokenClaims>(token, &decoding_key, &validation) {
        Ok(token_data) => {
            // Verify it's an access token
            if token_data.claims.token_type != "access" {
                return Err(JwtError::InvalidToken);
            }
            Ok(token_data.claims)
        }
        Err(err) => {
            match err.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => Err(JwtError::TokenExpired),
                _ => Err(JwtError::DecodingError),
            }
        }
    }
}

/// Validate and decode a refresh token
pub fn decode_refresh_token(
    config: &JwtConfig,
    token: &str
) -> Result<RefreshTokenClaims, JwtError> {
    let decoding_key = jwt::DecodingKey::from_secret(config.secret.as_ref());
    let validation = jwt::Validation::new(jwt::Algorithm::HS256);

    match jwt::decode::<RefreshTokenClaims>(token, &decoding_key, &validation) {
        Ok(token_data) => {
            // Verify it's a refresh token
            if token_data.claims.token_type != "refresh" {
                return Err(JwtError::InvalidToken);
            }
            Ok(token_data.claims)
        }
        Err(err) => {
            match err.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => Err(JwtError::TokenExpired),
                _ => Err(JwtError::DecodingError),
            }
        }
    }
}

