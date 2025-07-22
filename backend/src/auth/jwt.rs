use std::sync::LazyLock;

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

use crate::core::JwtConfig;

#[derive(Debug, Error)]
pub enum JwtError {
    #[error("Failed to encode JWT token")]
    EncodingError(jwt::errors::Error),

    #[error("Failed to decode JWT token")]
    DecodingError(jwt::errors::Error),

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

        let (status, error_message) = match self {
            Self::EncodingError(_) => (http::StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            Self::DecodingError(_) => (http::StatusCode::UNAUTHORIZED, "Invalid or missing authentication token".to_string()),
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

/// Common claims shared by both token types
#[derive(Debug, Deserialize, Serialize)]
struct CommonClaims {
    pub sub: String,        // Subject (user ID)
    pub exp: i64,          // Expiration time
    pub iat: i64,          // Issued at
    pub jti: String,       // JWT ID (unique identifier)
    pub token_type: String, // "access" or "refresh"
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
    pub access_token_expires_in: i64, // Seconds until access token expires
    pub refresh_token_expires_in: i64, // Seconds until refresh token expires
}

trait ClaimsWithTokenType {
    fn token_type(&self) -> &str;
}

impl ClaimsWithTokenType for AccessTokenClaims {
    fn token_type(&self) -> &str { &self.token_type }
}

impl ClaimsWithTokenType for RefreshTokenClaims {
    fn token_type(&self) -> &str { &self.token_type }
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

static JWT_HEADER: LazyLock<jwt::Header> = LazyLock::new(|| jwt::Header::new(jwt::Algorithm::HS256));
const REFRESH_TOKEN_TYPE: &str = "refresh";
const ACCESS_TOKEN_TYPE: &str = "access";

/// Generate a new access token
pub fn generate_access_token(config: &JwtConfig, user_id: i64, user_name: &str, tenant_id: Option<i64>) -> Result<String, JwtError> {
    let now = Utc::now().timestamp();
    let encoding_key = jwt::EncodingKey::from_secret(config.secret.as_ref());
    let claims = AccessTokenClaims {
        sub: user_id.to_string(),
        username: user_name.to_string(),
        tenant_id,
        exp: now + config.access_token_expiry,
        iat: now,
        jti: Uuid::new_v4().to_string(),
        token_type: ACCESS_TOKEN_TYPE.to_string(),
    };
    jwt::encode(&JWT_HEADER, &claims, &encoding_key).map_err(JwtError::EncodingError)
}

/// Generate a new refresh token
pub fn generate_refresh_token(config: &JwtConfig, user_id: i64) -> Result<String, JwtError> {
    let now = Utc::now().timestamp();
    let encoding_key = jwt::EncodingKey::from_secret(config.secret.as_ref());
    let claims = RefreshTokenClaims {
        sub: user_id.to_string(),
        exp: now + config.refresh_token_expiry,
        iat: now,
        jti: Uuid::new_v4().to_string(),
        token_type: REFRESH_TOKEN_TYPE.to_string(),
    };
    jwt::encode(&JWT_HEADER, &claims, &encoding_key).map_err(JwtError::EncodingError)
}

pub fn decode_access_token_from_req(config: &JwtConfig, req: &Request) -> Result<AccessTokenClaims, JwtError> {
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
    decode_access_token(config, token)
}

/// Validate and decode an access token
pub fn decode_access_token(config: &JwtConfig, token: &str) -> Result<AccessTokenClaims, JwtError> {
    decode_token::<AccessTokenClaims>(token, config, ACCESS_TOKEN_TYPE)
}

/// Validate and decode a refresh token
pub fn decode_refresh_token(config: &JwtConfig, token: &str) -> Result<RefreshTokenClaims, JwtError> {
    decode_token::<RefreshTokenClaims>(token, config, REFRESH_TOKEN_TYPE)
}

fn decode_token<T>(token: &str, config: &JwtConfig, expected_token_type: &str) -> Result<T, JwtError>
where T: serde::de::DeserializeOwned + ClaimsWithTokenType
{
    let decoding_key = jwt::DecodingKey::from_secret(config.secret.as_ref());
    let mut validation = jwt::Validation::new(jwt::Algorithm::HS256);
    validation.leeway = 0; // Set leeway to 0 to ensure strict expiration checking
    let token = jwt::decode::<T>(token, &decoding_key, &validation)?;
    let valid = token.claims.token_type() == expected_token_type;
    valid.then_some(()).ok_or(JwtError::InvalidToken)?;
    Ok(token.claims)
}

/// Maps jsonwebtoken errors to our custom JwtError type
impl From<jwt::errors::Error> for JwtError {
    fn from(e: jwt::errors::Error) -> Self {
        match e.kind() {
            jwt::errors::ErrorKind::ExpiredSignature => JwtError::TokenExpired,
            jwt::errors::ErrorKind::InvalidToken => JwtError::InvalidToken,
            jwt::errors::ErrorKind::Json(_) => JwtError::InvalidToken,
            _ => JwtError::DecodingError(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{HeaderValue, Request};

    fn create_test_config() -> JwtConfig {
        JwtConfig {
            secret: "test_secret_key_for_jwt_testing".to_string(),
            access_token_expiry: 3600, // 1 hour
            refresh_token_expiry: 86400, // 24 hours
        }
    }

    fn create_short_expiry_config() -> JwtConfig {
        JwtConfig {
            secret: "test_secret_key_for_jwt_testing".to_string(),
            access_token_expiry: 1, // 1 second
            refresh_token_expiry: 2, // 2 seconds
        }
    }

    #[test]
    fn test_generate_access_token_success() {
        let config = create_test_config();
        let user_id = 123;
        let username = "test_user";
        let tenant_id = Some(456);

        let token = generate_access_token(&config, user_id, username, tenant_id).unwrap();

        // Token should be non-empty and contain JWT structure (header.payload.signature)
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
    }

    #[test]
    fn test_generate_refresh_token_success() {
        let config = create_test_config();
        let user_id = 123;

        let token = generate_refresh_token(&config, user_id).unwrap();

        // Token should be non-empty and contain JWT structure
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
    }

    #[test]
    fn test_decode_access_token_success() {
        let config = create_test_config();
        let user_id = 123;
        let username = "test_user";
        let tenant_id = Some(456);

        let token = generate_access_token(&config, user_id, username, tenant_id).unwrap();
        let claims = decode_access_token(&config, &token).unwrap();

        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.username, username);
        assert_eq!(claims.tenant_id, tenant_id);
        assert_eq!(claims.token_type, ACCESS_TOKEN_TYPE);
        assert!(claims.exp > claims.iat);
        assert!(!claims.jti.is_empty());
    }

    #[test]
    fn test_decode_refresh_token_success() {
        let config = create_test_config();
        let user_id = 123;

        let token = generate_refresh_token(&config, user_id).unwrap();
        let claims = decode_refresh_token(&config, &token).unwrap();

        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.token_type, REFRESH_TOKEN_TYPE);
        assert!(claims.exp > claims.iat);
        assert!(!claims.jti.is_empty());
    }

    #[test]
    fn test_decode_access_token_wrong_secret() {
        let config = create_test_config();
        let mut wrong_config = config.clone();
        wrong_config.secret = "wrong_secret".to_string();

        let user_id = 123;
        let username = "test_user";
        let token = generate_access_token(&config, user_id, username, None).unwrap();

        let result = decode_access_token(&wrong_config, &token);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), JwtError::DecodingError(_)));
    }

    #[test]
    fn test_decode_invalid_token() {
        let config = create_test_config();
        let invalid_token = "invalid.token.format";

        let result = decode_access_token(&config, invalid_token);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), JwtError::DecodingError(_)));
    }

    #[test]
    fn test_decode_malformed_token() {
        let config = create_test_config();
        let malformed_token = "not_a_jwt_token";

        let result = decode_access_token(&config, malformed_token);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), JwtError::InvalidToken));
    }

    #[test]
    fn test_token_expiry() {
        let config = create_short_expiry_config();
        let user_id = 123;
        let username = "test_user";

        let token = generate_access_token(&config, user_id, username, None).unwrap();

        // Should work immediately
        let claims = decode_access_token(&config, &token).unwrap();
        assert_eq!(claims.sub, user_id.to_string());

        // Wait for token to expire
        std::thread::sleep(std::time::Duration::from_secs(2));

        // Should now fail with expiry error
        let result = decode_access_token(&config, &token);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), JwtError::TokenExpired));
    }

    #[test]
    fn test_access_token_used_as_refresh_token() {
        let config = create_test_config();
        let user_id = 123;
        let username = "test_user";

        let access_token = generate_access_token(&config, user_id, username, None).unwrap();

        // Try to decode access token as refresh token - should fail
        let result = decode_refresh_token(&config, &access_token);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), JwtError::InvalidToken));
    }

    #[test]
    fn test_refresh_token_used_as_access_token() {
        let config = create_test_config();
        let user_id = 123;

        let refresh_token = generate_refresh_token(&config, user_id).unwrap();

        // Try to decode refresh token as access token - should fail
        let result = decode_access_token(&config, &refresh_token);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), JwtError::InvalidToken));
    }

    #[test]
    fn test_decode_access_token_from_req_success() {
        let config = create_test_config();
        let user_id = 123;
        let username = "test_user";

        let token = generate_access_token(&config, user_id, username, None).unwrap();

        let mut req = Request::new(Body::empty());
        req.headers_mut().insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", token)).unwrap()
        );

        let claims = decode_access_token_from_req(&config, &req).unwrap();
        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.username, username);
    }

    #[test]
    fn test_decode_access_token_from_req_missing_header() {
        let config = create_test_config();
        let req = Request::new(Body::empty());

        let result = decode_access_token_from_req(&config, &req);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), JwtError::InvalidAuthorizationHeader));
    }

    #[test]
    fn test_decode_access_token_from_req_wrong_format() {
        let config = create_test_config();
        let mut req = Request::new(Body::empty());

        // Missing "Bearer " prefix
        req.headers_mut().insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_str("some_token").unwrap()
        );

        let result = decode_access_token_from_req(&config, &req);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), JwtError::InvalidAuthorizationHeader));
    }

    #[test]
    fn test_token_response_creation() {
        let config = create_test_config();
        let access_token = "access_token_string".to_string();
        let refresh_token = "refresh_token_string".to_string();

        let response = TokenResponse::new(access_token.clone(), refresh_token.clone(), &config);

        assert_eq!(response.access_token, access_token);
        assert_eq!(response.refresh_token, refresh_token);
        assert_eq!(response.access_token_expires_in, config.access_token_expiry);
        assert_eq!(response.refresh_token_expires_in, config.refresh_token_expiry);
    }

    #[test]
    fn test_different_tokens_have_different_jtis() {
        let config = create_test_config();
        let user_id = 123;
        let username = "test_user";

        let token1 = generate_access_token(&config, user_id, username, None).unwrap();
        let token2 = generate_access_token(&config, user_id, username, None).unwrap();

        let claims1 = decode_access_token(&config, &token1).unwrap();
        let claims2 = decode_access_token(&config, &token2).unwrap();

        // JTIs should be different for different tokens
        assert_ne!(claims1.jti, claims2.jti);
    }

    #[test]
    fn test_access_token_contains_correct_tenant_info() {
        let config = create_test_config();
        let user_id = 123;
        let username = "test_user";

        // Test with tenant
        let tenant_id = Some(456);
        let token_with_tenant = generate_access_token(&config, user_id, username, tenant_id).unwrap();
        let claims_with_tenant = decode_access_token(&config, &token_with_tenant).unwrap();
        assert_eq!(claims_with_tenant.tenant_id, tenant_id);

        // Test without tenant
        let token_without_tenant = generate_access_token(&config, user_id, username, None).unwrap();
        let claims_without_tenant = decode_access_token(&config, &token_without_tenant).unwrap();
        assert_eq!(claims_without_tenant.tenant_id, None);
    }
}