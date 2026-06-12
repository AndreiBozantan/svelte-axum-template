use axum::body::Body;
use axum::extract::FromRequestParts;
use axum::extract::State;
use axum::http::Request;
use axum::http::request::Parts;
use axum::response::Response;

use crate::platform::api;
use crate::platform::common;
use crate::platform::config;
use crate::platform::jwt;
use crate::platform::shared;

use crate::platform::identity::oauth;
use crate::platform::identity::tokens;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid credentials")]
    InvalidCredentials,

    #[error("token expired or invalid")]
    InvalidToken,

    #[error("password hashing failed: {0}")]
    PasswordHashingFailed(#[from] argon2::password_hash::Error),

    #[error("jwt operation failed: {0}")]
    JwtOperationFailed(#[from] jwt::Error),

    #[error("token operation failed: {0}")]
    TokenOperationFailed(#[from] tokens::utils::Error),

    #[error("internal error: {0}")]
    InternalFault(String),
}

impl From<Error> for api::Error {
    fn from(error: Error) -> Self {
        // TODO: use structured logging here
        tracing::error!("auth error: {error}");
        match error {
            Error::InvalidCredentials => Self::invalid_credentials(),
            Error::InvalidToken => Self::invalid_token(),
            Error::TokenOperationFailed(token_error) => token_error.into(),
            Error::JwtOperationFailed(jwt_error) => jwt_error.into(),
            _ => Self::internal(),
        }
    }
}

impl From<shared::db::Error> for Error {
    fn from(error: shared::db::Error) -> Self {
        Self::InternalFault(format!("database operation failed {error}"))
    }
}

pub fn check_oauth_config(config: &config::OAuthSettings) {
    if let Err(error) = oauth::validate_google_config(config) {
        tracing::warn!("Google OAuth config is incomplete. {error}");
    }
}

pub async fn middleware(
    State(context): State<common::ArcContext>,
    mut req: Request<Body>,
    next: axum::middleware::Next,
) -> Result<Response, api::Error> {
    let claims = tokens::utils::decode_token_from_req(&context.jwt, &req, jwt::TokenType::Access)?;

    tracing::debug!(
        user_id = claims.sub,
        email = claims.email,
        tenant_id = ?claims.tenant_id,
        "Authenticated user accessing API"
    );

    req.extensions_mut().insert(claims);
    Ok(next.run(req).await)
}

impl<S> FromRequestParts<S> for jwt::TokenClaims
where
    S: Send + Sync,
{
    type Rejection = api::Error;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        parts.extensions.get().cloned().ok_or_else(api::Error::invalid_token)
    }
}

use argon2::password_hash as ar2;
use std::sync;

/// Hash a password using Argon2
pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    use ar2::PasswordHasher;
    const ARGON2_MEM_COST: u32 = 19456;
    const ARGON2_TIME_COST: u32 = 2;
    const ARGON2_PARALLELISM: u32 = 1;
    let salt = ar2::SaltString::generate(ar2::rand_core::OsRng);
    let params = argon2::Params::new(ARGON2_MEM_COST, ARGON2_TIME_COST, ARGON2_PARALLELISM, None)?;
    let hasher = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let hash = hasher.hash_password(password.as_bytes(), &salt)?;
    Ok(hash.to_string())
}

/// Verify a password against a hash
pub fn verify_password(
    password: &str,
    hash: &str,
) -> Result<bool, ar2::Error> {
    use ar2::PasswordVerifier;
    use argon2::Argon2;
    let parsed_hash = ar2::PasswordHash::new(hash)?;
    match Argon2::default().verify_password(password.as_bytes(), &parsed_hash) {
        Ok(()) => Ok(true),
        Err(ar2::Error::Password) => Ok(false),
        Err(e) => Err(e),
    }
}

static DUMMY_HASH: sync::LazyLock<Result<String, Error>> =
    sync::LazyLock::new(|| Ok(hash_password("dummy_password_for_timing")?));

pub fn dummy_hash() -> Result<&'static str, Error> {
    DUMMY_HASH
        .as_ref()
        .map(std::string::String::as_str)
        .map_err(|_| Error::InternalFault("dummy hash init failed".to_string()))
}
