use std::fs;
use std::io::Write;

use chrono::DateTime;
use chrono::NaiveDateTime;
use chrono::Utc;
use jsonwebtoken as jwt;
use rand::TryRng;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;
use uuid::Uuid;

use crate::platform::common;
use crate::platform::config;

#[rustfmt::skip]
#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed to encode JWT token")]
    EncodingFailed(jwt::errors::Error),

    #[error("Failed to decode JWT token")]
    DecodingFailed(jwt::errors::Error),

    #[error("File system operation failed")]
    FileSystemOperationFailed { #[from] source: std::io::Error },

    #[error("Random number generation operation failed")]
    RngOperationFailed { #[from] source: rand::rngs::SysError },

    #[error("Token has expired")]
    ExpiredToken,

    #[error("Invalid token")]
    InvalidToken,
}

/// Maps jsonwebtoken errors to our custom `JwtError` type
impl From<jwt::errors::Error> for Error {
    fn from(e: jwt::errors::Error) -> Self {
        match e.kind() {
            jwt::errors::ErrorKind::ExpiredSignature => Self::ExpiredToken,
            jwt::errors::ErrorKind::InvalidToken => Self::InvalidToken,
            jwt::errors::ErrorKind::Json(_) => Self::InvalidToken,
            jwt::errors::ErrorKind::InvalidSignature => Self::InvalidToken,
            jwt::errors::ErrorKind::InvalidAlgorithmName => Self::InvalidToken,
            jwt::errors::ErrorKind::InvalidAlgorithm => Self::InvalidToken,
            jwt::errors::ErrorKind::InvalidIssuer => Self::InvalidToken,
            jwt::errors::ErrorKind::InvalidAudience => Self::InvalidToken,
            jwt::errors::ErrorKind::InvalidSubject => Self::InvalidToken,
            jwt::errors::ErrorKind::ImmatureSignature => Self::InvalidToken,
            jwt::errors::ErrorKind::Base64(_) => Self::InvalidToken,
            jwt::errors::ErrorKind::Utf8(_) => Self::InvalidToken,
            _ => Self::DecodingFailed(e),
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
    pub fn user_id(&self) -> Result<common::UserId, Error> {
        Ok(common::UserId(
            self.sub.parse::<i64>().map_err(|_| Error::InvalidToken)?,
        ))
    }

    pub const fn tenant_id(&self) -> common::TenantId {
        common::TenantId(self.tenant_id)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TokenWithClaims {
    pub value: String,
    pub claims: TokenClaims,
}

#[derive(Clone)]
pub struct Context {
    pub encoding_key: jwt::EncodingKey,
    pub decoding_key: jwt::DecodingKey,
    pub validation: jwt::Validation,
    pub access_token_expiry: u32,
    pub refresh_token_expiry: u32,
}

pub fn create_context(
    settings: &config::JwtSettings,
    secret: &str,
) -> Context {
    let encoding_key = jwt::EncodingKey::from_secret(secret.as_ref());
    let decoding_key = jwt::DecodingKey::from_secret(secret.as_ref());
    let mut validation = jwt::Validation::new(jwt::Algorithm::HS256);
    validation.validate_exp = true; // explicitly enforce expiry so library default changes cannot silently disable it
    validation.leeway = 5; // small leeway tolerates minor clock skew between distributed instances

    Context {
        encoding_key,
        decoding_key,
        validation,
        access_token_expiry: 60 * settings.access_token_expiry_minutes,
        refresh_token_expiry: 60 * 60 * 24 * settings.refresh_token_expiry_days,
    }
}

/// Generate a new access or refresh token.
pub fn generate_token(
    ctx: &Context,
    user_id: i64,
    tenant_id: i64,
    email: &str,
    token_type: TokenType,
) -> Result<TokenWithClaims, Error> {
    let now = Utc::now().timestamp();
    let expiry = match token_type {
        TokenType::Access => ctx.access_token_expiry,
        TokenType::Refresh => ctx.refresh_token_expiry,
    };
    let header = jwt::Header::new(jwt::Algorithm::HS256);
    let claims = TokenClaims {
        sub: user_id.to_string(),
        tenant_id,
        email: email.to_string(),
        exp: now + i64::from(expiry),
        iat: now,
        jti: Uuid::new_v4().to_string(),
        token_type,
    };
    let token = jwt::encode(&header, &claims, &ctx.encoding_key).map_err(Error::EncodingFailed)?;
    Ok(TokenWithClaims { value: token, claims })
}

pub fn get_token_expiration_as_naive_utc(timestamp: i64) -> Result<NaiveDateTime, Error> {
    DateTime::from_timestamp(timestamp, 0)
        .map(|dt| dt.naive_utc())
        .ok_or(Error::InvalidToken)
}

/// Validate and decode an access or refresh token
pub fn decode_token(
    ctx: &Context,
    token: &str,
    token_type: TokenType,
) -> Result<TokenClaims, Error> {
    let token_data = jwt::decode::<TokenClaims>(token, &ctx.decoding_key, &ctx.validation)?;
    let valid = token_data.claims.token_type == token_type;
    valid.then_some(token_data.claims).ok_or(Error::InvalidToken)
}

/// Loads or creates a JWT secret
pub fn get_jwt_secret() -> Result<String, Error> {
    let secret_file_path = config::AppSettings::get_config_dir()?.join(".jwt.secret");
    get_jwt_secret_with_file_path(&secret_file_path)
}

pub fn get_jwt_secret_with_file_path(secret_file_path: &std::path::Path) -> Result<String, Error> {
    // check persisted secret file
    if let Ok(file_secret) = fs::read_to_string(secret_file_path) {
        let trimmed_secret = file_secret.trim();
        if !trimmed_secret.is_empty() && trimmed_secret.len() >= 32 {
            return Ok(trimmed_secret.to_string());
        }
    }

    // write the secret to file atomically and with restricted permissions
    let new_secret = generate_secure_secret()?;
    let parent_dir = secret_file_path
        .parent()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "No parent directory"))?;
    let temp_file_path = parent_dir.join(format!(".jwt.secret.tmp.{}", Uuid::new_v4()));

    // open/create the temp file with restricted permissions (0o600)
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600); // owner read/write only
    }

    let write_and_rename = || -> Result<(), std::io::Error> {
        let mut temp_file = options.open(&temp_file_path)?;
        temp_file.write_all(new_secret.as_bytes())?;
        temp_file.sync_all()?;
        fs::rename(&temp_file_path, secret_file_path)?;
        Ok(())
    };

    if let Err(err) = write_and_rename() {
        let _ = fs::remove_file(&temp_file_path);
        return Err(err.into());
    }

    Ok(new_secret)
}

/// Generates a cryptographically secure random secret
fn generate_secure_secret() -> Result<String, Error> {
    let mut bytes = [0u8; 32];
    rand::rngs::SysRng.try_fill_bytes(&mut bytes)?;
    Ok(hex::encode(bytes))
}
