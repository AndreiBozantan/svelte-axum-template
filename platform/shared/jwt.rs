use std::fs;

use chrono::DateTime;
use chrono::NaiveDateTime;
use chrono::Utc;
use jsonwebtoken as jwt;
use rand::TryRng;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;
use uuid::Uuid;

use crate::common::ApiError;
use crate::config;

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
    RngOperationFailed { source: rand::rngs::SysError },

    #[error("Token has expired")]
    TokenExpired,

    #[error("Invalid token")]
    InvalidToken,
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

impl JwtError {
    #[must_use]
    pub fn into_api_error(self) -> ApiError {
        #[allow(clippy::match_same_arms)]
        match self {
            Self::RngOperationFailed { .. } => ApiError::internal(),
            Self::FileSystemOperationFailed { .. } => ApiError::internal(),
            Self::EncodingFailed(_) => ApiError::internal(),
            Self::DecodingFailed(_) => ApiError::invalid_token(),
            Self::InvalidToken => ApiError::invalid_token(),
            Self::TokenExpired => ApiError::expired_token(),
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TokenType {
    Access,
    Refresh,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TokenClaims {
    pub sub: String,
    pub tenant_id: i64,
    pub email: String,
    pub exp: i64,
    pub iat: i64,
    pub jti: String,
    pub token_type: TokenType,
}

impl TokenClaims {
    pub fn user_id(&self) -> Result<i64, JwtError> {
        self.sub.parse::<i64>().map_err(|_| JwtError::InvalidToken)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TokenWithClaims {
    pub value: String,
    pub claims: TokenClaims,
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
    pub fn new(settings: &config::JwtSettings, secret: &str) -> Result<Self, JwtError> {
        let encoding_key = jwt::EncodingKey::from_secret(secret.as_ref());
        let decoding_key = jwt::DecodingKey::from_secret(secret.as_ref());
        let mut validation = jwt::Validation::new(jwt::Algorithm::HS256);
        validation.validate_exp = true; // explicitly enforce expiry so library default changes cannot silently disable it
        validation.leeway = 5; // small leeway tolerates minor clock skew between distributed instances

        Ok(Self {
            encoding_key,
            decoding_key,
            validation,
            access_token_expiry: 60 * i64::from(settings.access_token_expiry_minutes),
            refresh_token_expiry: 60 * 60 * 24 * i64::from(settings.refresh_token_expiry_days),
        })
    }
}

/// Generate a new access or refresh token.
pub fn generate_token(
    ctx: &JwtContext,
    user_id: i64,
    tenant_id: i64,
    email: &str,
    token_type: TokenType,
    expiry: i64,
) -> Result<TokenWithClaims, JwtError> {
    let now = Utc::now().timestamp();
    let header = jwt::Header::new(jwt::Algorithm::HS256);
    let claims = TokenClaims {
        sub: user_id.to_string(),
        tenant_id,
        email: email.to_string(),
        exp: now + expiry,
        iat: now,
        jti: Uuid::new_v4().to_string(),
        token_type,
    };
    let token = jwt::encode(&header, &claims, &ctx.encoding_key).map_err(JwtError::EncodingFailed)?;
    Ok(TokenWithClaims { value: token, claims })
}

pub fn get_token_expiration_as_naive_utc(timestamp: i64) -> Result<NaiveDateTime, JwtError> {
    DateTime::from_timestamp(timestamp, 0)
        .map(|dt| dt.naive_utc())
        .ok_or(JwtError::InvalidToken)
}

/// Validate and decode an access or refresh token
pub fn decode_token(ctx: &JwtContext, token: &str, token_type: TokenType) -> Result<TokenClaims, JwtError> {
    let token_data = jwt::decode::<TokenClaims>(token, &ctx.decoding_key, &ctx.validation)?;
    let valid = token_data.claims.token_type == token_type;
    valid.then_some(token_data.claims).ok_or(JwtError::InvalidToken)
}

/// Loads or creates a JWT secret
pub fn get_jwt_secret() -> Result<String, JwtError> {
    // check persisted secret file
    let secret_file_path = config::AppSettings::get_config_dir()?.join(".jwt.secret");
    if let Ok(file_secret) = fs::read_to_string(&secret_file_path) {
        let trimmed_secret = file_secret.trim();
        if !trimmed_secret.is_empty() && trimmed_secret.len() >= 32 {
            return Ok(trimmed_secret.to_string());
        }
    }

    // write the secret to file with restricted permissions
    let new_secret = generate_secure_secret()?;
    fs::write(&secret_file_path, &new_secret)?;

    // set file permissions to be readable only by owner (Unix-like systems)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&secret_file_path)?.permissions();
        perms.set_mode(0o600); // rw-------
        fs::set_permissions(&secret_file_path, perms)?;
    }

    Ok(new_secret)
}

/// Generates a cryptographically secure random secret
fn generate_secure_secret() -> Result<String, JwtError> {
    let mut bytes = [0u8; 32];
    rand::rngs::SysRng
        .try_fill_bytes(&mut bytes)
        .map_err(|e| JwtError::RngOperationFailed { source: e })?;
    Ok(hex::encode(bytes))
}
