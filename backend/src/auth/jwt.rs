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

#[derive(Debug, Error)]
pub enum JwtError {
    #[error("Failed to encode JWT token")]
    EncodingFailed(jwt::errors::Error),

    #[error("Failed to decode JWT token")]
    DecodingFailed(jwt::errors::Error),

    #[error("File system operation failed")]
    FileSystemOperationFailed{ #[from] source: std::io::Error },

    #[error("Random number generation operation failed")]
    RngOperationFailed{ source: TryRngError },

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
    rand::rngs::OsRng.try_fill_bytes(&mut bytes).map_err(|e| JwtError::RngOperationFailed{ source: e })?;
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

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{HeaderValue, Request};

    use super::*;
    use crate::cfg::{self, JwtSettings};

    fn create_test_context() -> JwtContext {
        let settings = cfg::JwtSettings {
            access_token_expiry: 3600,   // 1 hour
            refresh_token_expiry: 86400, // 24 hours
        };
        // For tests, create a JwtContext with a fixed secret
        let secret = "test_secret_key_for_jwt_testing";
        JwtContext::new(&settings, secret).unwrap()
    }

    #[test]
    fn test_generate_access_token_success() {
        let ctx = create_test_context();
        let user_id = 123;
        let username = "test_user";
        let tenant_id = Some(456);

        let token = generate_access_token(&ctx, user_id, username, tenant_id).unwrap();

        // Token should be non-empty and contain JWT structure (header.payload.signature)
        let parts = token.split('.');
        assert_eq!(parts.count(), 3);
    }

    #[test]
    fn test_generate_refresh_token_success() {
        let ctx = create_test_context();
        let user_id = 123;

        let token = generate_refresh_token(&ctx, user_id).unwrap();

        // Token should be non-empty and contain JWT structure
        let parts = token.split('.');
        assert_eq!(parts.count(), 3);
    }

    #[test]
    fn test_decode_access_token_success() {
        let ctx = create_test_context();
        let user_id = 123;
        let username = "test_user";
        let tenant_id = Some(456);

        let token = generate_access_token(&ctx, user_id, username, tenant_id).unwrap();
        let claims = decode_access_token(&ctx, &token).unwrap();

        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.username, username);
        assert_eq!(claims.tenant_id, tenant_id);
        assert_eq!(claims.token_type, TokenType::Access);
        assert!(claims.exp > claims.iat);
        assert!(!claims.jti.is_empty());
    }

    #[test]
    fn test_decode_refresh_token_success() {
        let ctx = create_test_context();
        let user_id = 123;

        let token = generate_refresh_token(&ctx, user_id).unwrap();
        let claims = decode_refresh_token(&ctx, &token).unwrap();

        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.token_type, TokenType::Refresh);
        assert!(claims.exp > claims.iat);
        assert!(!claims.jti.is_empty());
    }

    #[test]
    fn test_decode_access_token_wrong_secret() {
        // Create a context with a different secret
        let settings = cfg::JwtSettings {
            access_token_expiry: 3600,   // 1 hour
            refresh_token_expiry: 86400, // 24 hours
        };
        let wrong_secret = "wrong_secret_for_testing_1234567890";
        let wrong_ctx = JwtContext::new(&settings, wrong_secret).unwrap();
        let ctx = create_test_context();

        let user_id = 123;
        let username = "test_user";
        let token = generate_access_token(&ctx, user_id, username, None).unwrap();
        let result = decode_access_token(&wrong_ctx, &token);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), JwtError::DecodingFailed(_)));
    }

    #[test]
    fn test_decode_invalid_token() {
        let ctx = create_test_context();
        let invalid_token = "invalid.token.format";

        let result = decode_access_token(&ctx, invalid_token);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), JwtError::DecodingFailed(_)));
    }

    #[test]
    fn test_decode_malformed_token() {
        let ctx = create_test_context();
        let malformed_token = "not_a_jwt_token";

        let result = decode_access_token(&ctx, malformed_token);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), JwtError::InvalidToken));
    }

    #[test]
    fn test_token_expiry() {
        // Create a context with short expiry times for testing
        let secret = "test_secret_key_for_jwt_testing";
        let settings = JwtSettings {
            access_token_expiry: 1,  // 1 second
            refresh_token_expiry: 2, // 2 seconds
        };
        let ctx = JwtContext::new(&settings, secret).unwrap();

        let user_id = 123;
        let username = "test_user";
        let token = generate_access_token(&ctx, user_id, username, None).unwrap();

        // Should work immediately
        let claims = decode_access_token(&ctx, &token).unwrap();
        assert_eq!(claims.sub, user_id.to_string());

        // Wait for token to expire
        std::thread::sleep(std::time::Duration::from_secs(2));

        // Should now fail with expiry error
        let result = decode_access_token(&ctx, &token);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), JwtError::TokenExpired));
    }

    #[test]
    fn test_access_token_used_as_refresh_token() {
        let ctx = create_test_context();
        let user_id = 123;
        let username = "test_user";

        let access_token = generate_access_token(&ctx, user_id, username, None).unwrap();

        // Try to decode access token as refresh token - should fail
        let result = decode_refresh_token(&ctx, &access_token);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), JwtError::InvalidToken));
    }

    #[test]
    fn test_refresh_token_used_as_access_token() {
        let ctx = create_test_context();
        let user_id = 123;

        let refresh_token = generate_refresh_token(&ctx, user_id).unwrap();

        // Try to decode refresh token as access token - should fail
        let result = decode_access_token(&ctx, &refresh_token);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), JwtError::InvalidToken));
    }

    #[test]
    fn test_decode_access_token_from_req_success() {
        let ctx = create_test_context();
        let user_id = 123;
        let username = "test_user";

        let token = generate_access_token(&ctx, user_id, username, None).unwrap();

        let mut req = Request::new(Body::empty());
        req.headers_mut().insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );

        let claims = decode_access_token_from_req(&ctx, &req).unwrap();
        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.username, username);
    }

    #[test]
    fn test_decode_access_token_from_req_missing_header() {
        let ctx = create_test_context();
        let req = Request::new(Body::empty());

        let result = decode_access_token_from_req(&ctx, &req);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), JwtError::InvalidAuthorizationHeader));
    }

    #[test]
    fn test_decode_access_token_from_req_wrong_format() {
        let ctx = create_test_context();
        let mut req = Request::new(Body::empty());

        // Missing "Bearer " prefix
        req.headers_mut().insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_str("some_token").unwrap(),
        );

        let result = decode_access_token_from_req(&ctx, &req);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), JwtError::InvalidAuthorizationHeader));
    }

    #[test]
    fn test_token_response_creation() {
        let ctx = create_test_context();
        let access_token = "access_token_string".to_string();
        let refresh_token = "refresh_token_string".to_string();

        let response = TokenResponse::new(&ctx, access_token.clone(), refresh_token.clone());

        assert_eq!(response.access_token, access_token);
        assert_eq!(response.refresh_token, refresh_token);
        assert_eq!(response.access_token_expires_in, ctx.access_token_expiry);
        assert_eq!(response.refresh_token_expires_in, ctx.refresh_token_expiry);
    }

    #[test]
    fn test_different_tokens_have_different_jwt_ids() {
        let ctx = create_test_context();
        let user_id = 123;
        let username = "test_user";

        let token1 = generate_access_token(&ctx, user_id, username, None).unwrap();
        let token2 = generate_access_token(&ctx, user_id, username, None).unwrap();

        let claims1 = decode_access_token(&ctx, &token1).unwrap();
        let claims2 = decode_access_token(&ctx, &token2).unwrap();

        // JTIs should be different for different tokens
        assert_ne!(claims1.jti, claims2.jti);
    }

    #[test]
    fn test_access_token_contains_correct_tenant_info() {
        let ctx = create_test_context();
        let user_id = 123;
        let username = "test_user";

        // Test with tenant
        let tenant_id = Some(456);
        let token_with_tenant = generate_access_token(&ctx, user_id, username, tenant_id).unwrap();
        let claims_with_tenant = decode_access_token(&ctx, &token_with_tenant).unwrap();
        assert_eq!(claims_with_tenant.tenant_id, tenant_id);

        // Test without tenant
        let token_without_tenant = generate_access_token(&ctx, user_id, username, None).unwrap();
        let claims_without_tenant = decode_access_token(&ctx, &token_without_tenant).unwrap();
        assert_eq!(claims_without_tenant.tenant_id, None);
    }
}
