use chrono::Utc;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation, Algorithm};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use thiserror::Error;

#[derive(Debug, Clone)]
pub enum ClientType {
    Web,      // Browser-based applications
    Mobile,   // Mobile applications
    Service,  // Service-to-service communication
}

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

#[derive(Debug, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub sub: String,        // Subject (user ID)
    pub username: String,   // Username for convenience
    pub tenant_id: Option<i64>, // Tenant ID if applicable
    pub exp: i64,          // Expiration time
    pub iat: i64,          // Issued at
    pub jti: String,       // JWT ID (unique identifier)
    pub token_type: String, // "access"
}

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Clone)]
pub struct JwtConfig {
    pub secret: String,
    pub access_token_expiry: i64,  // In seconds (e.g., 15 minutes = 900)
    pub refresh_token_expiry: i64, // In seconds (e.g., 7 days = 604800)
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            secret: "your-secret-key-change-this-in-production".to_string(),
            access_token_expiry: 900,    // 15 minutes
            refresh_token_expiry: 604800, // 7 days
        }
    }
}

/// Generate a new access token
pub fn generate_access_token(config: &JwtConfig, user_id: i64, user_name: &str, tenant_id: Option<i64>) -> Result<String, JwtError> {
    let now = Utc::now().timestamp();
    let claims = AccessTokenClaims {
        sub: user_id.to_string(),
        username: user_name.to_string(),
        tenant_id,
        exp: now + config.access_token_expiry,
        iat: now,
        jti: Uuid::new_v4().to_string(),
        token_type: "access".to_string(),
    };

    let header = Header::new(Algorithm::HS256);
    let encoding_key = EncodingKey::from_secret(config.secret.as_ref());

    encode(&header, &claims, &encoding_key)
        .map_err(JwtError::EncodingError)
}

/// Generate a new refresh token with custom expiration
pub fn generate_refresh_token_with_expiry(config: &JwtConfig, user_id: i64, expiry_seconds: i64) -> Result<String, JwtError> {
    let now = Utc::now().timestamp();
    let claims = RefreshTokenClaims {
        sub: user_id.to_string(),
        exp: now + expiry_seconds,
        iat: now,
        jti: Uuid::new_v4().to_string(),
        token_type: "refresh".to_string(),
    };

    let header = Header::new(Algorithm::HS256);
    let encoding_key = EncodingKey::from_secret(config.secret.as_ref());

    encode(&header, &claims, &encoding_key)
        .map_err(JwtError::EncodingError)
}

/// Generate a new refresh token with default expiration
pub fn generate_refresh_token(config: &JwtConfig, user_id: i64) -> Result<String, JwtError> {
    generate_refresh_token_with_expiry(config, user_id, config.refresh_token_expiry)
}

/// Generate refresh token based on client type
pub fn generate_refresh_token_for_client(config: &JwtConfig, user_id: i64, client_type: ClientType) -> Result<String, JwtError> {
    let expiry = match client_type {
        ClientType::Web => config.refresh_token_expiry,        // 7 days
        ClientType::Mobile => config.refresh_token_expiry * 4, // 28 days
        ClientType::Service => config.refresh_token_expiry * 13, // ~90 days
    };
    generate_refresh_token_with_expiry(config, user_id, expiry)
}

/// Validate and decode an access token
pub fn decode_access_token(config: &JwtConfig, token: &str) -> Result<AccessTokenClaims, JwtError> {
    let decoding_key = DecodingKey::from_secret(config.secret.as_ref());
    let validation = Validation::new(Algorithm::HS256);

    match decode::<AccessTokenClaims>(token, &decoding_key, &validation) {
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
    let decoding_key = DecodingKey::from_secret(config.secret.as_ref());
    let validation = Validation::new(Algorithm::HS256);

    match decode::<RefreshTokenClaims>(token, &decoding_key, &validation) {
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

