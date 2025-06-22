use axum::http;
use axum::extract::Request;
use axum::response::IntoResponse;
use axum::Json;
use chrono::Utc;
use jsonwebtoken as jwt;
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;
use thiserror::Error;

use crate::app::JwtConfig;

#[derive(Debug, Error)]
pub enum JwtError {
    #[error("Failed to encode JWT token")]
    EncodingError(#[from] jwt::errors::Error),

    #[error("Failed to decode JWT token")]
    DecodingError,

    #[error("Token has expired")]
    TokenExpired,

    #[error("Invalid token")]
    InvalidToken,
}

impl IntoResponse for JwtError {
    fn into_response(self) -> axum::response::Response {
        tracing::error!(
            error_type = %std::any::type_name::<Self>(),
            error_subtype = %std::any::type_name_of_val(&self),
            error_message = %self);

        let (status, error_message) = match self {
            Self::EncodingError(_) => (http::StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            Self::DecodingError => (http::StatusCode::UNAUTHORIZED, "Invalid or missing authentication token".to_string()),
            Self::TokenExpired => (http::StatusCode::UNAUTHORIZED, "Authentication token has expired".to_string()),
            Self::InvalidToken => (http::StatusCode::UNAUTHORIZED, "Invalid authentication token".to_string()),
        };

        let body = Json(json!({
            "result": "error",
            "message": error_message
        }));

        (status, body).into_response()
    }
}

// ...existing code...

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
    pub access_token_expires_in: i64, // Seconds until access token expires
    pub refresh_token_expires_in: i64, // Seconds until refresh token expires
}

impl TokenResponse {
    pub fn new(access_token: String, refresh_token: String, config: &JwtConfig) -> Self {
        Self {
            access_token,
            refresh_token,
            access_token_expires_in: config.access_token_expiry,
            refresh_token_expires_in: config.refresh_token_expiry,
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
    decode_token::<AccessTokenClaims>(token, config, "access", |c| &c.token_type)
}

/// Validate and decode a refresh token
pub fn decode_refresh_token(config: &JwtConfig, token: &str) -> Result<RefreshTokenClaims, JwtError> {
    decode_token::<RefreshTokenClaims>(token, config, "refresh", |c| &c.token_type)
}

fn decode_token<T>(token: &str, config: &JwtConfig, expected_token_type: &str, get_type: fn(&T) -> &str) -> Result<T, JwtError>
where T: serde::de::DeserializeOwned
{
    let decoding_key = jwt::DecodingKey::from_secret(config.secret.as_ref());
    let validation = jwt::Validation::new(jwt::Algorithm::HS256);
    let token = jwt::decode::<T>(token, &decoding_key, &validation).map_err(map_jwt_error)?;
    if expected_token_type != get_type(&token.claims) {
        return Err(JwtError::InvalidToken);
    }
    Ok(token.claims)
}

/// Maps jsonwebtoken errors to our custom JwtError type
fn map_jwt_error(err: jwt::errors::Error) -> JwtError {
    match err.kind() {
        jwt::errors::ErrorKind::ExpiredSignature => JwtError::TokenExpired,
        _ => JwtError::DecodingError,
    }
}