use axum::body::Body;
use axum::extract::FromRequestParts;
use axum::extract::State;
use axum::http::Request;
use axum::http::request::Parts;
use axum::response::Response;

use crate::api;
use crate::common;
use crate::identity::oauth;
use crate::identity::tokens;
use crate::jwt;
use crate::shared;

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

pub fn check_oauth_config(config: &crate::config::OAuthSettings) {
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

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts.extensions.get().cloned().ok_or_else(api::Error::invalid_token)
    }
}

use argon2::password_hash as ar2;

/// Hash a password using Argon2
pub fn hash_password(password: &str) -> Result<String, ar2::Error> {
    use ar2::PasswordHasher;
    use argon2::Argon2;
    let salt = ar2::SaltString::generate(ar2::rand_core::OsRng);
    let hash = Argon2::default().hash_password(password.as_bytes(), &salt)?;
    Ok(hash.to_string())
}

/// Verify a password against a hash
pub fn verify_password(password: &str, hash: &str) -> Result<bool, ar2::Error> {
    use ar2::PasswordVerifier;
    use argon2::Argon2;
    let parsed_hash = ar2::PasswordHash::new(hash)?;
    match Argon2::default().verify_password(password.as_bytes(), &parsed_hash) {
        Ok(()) => Ok(true),
        Err(ar2::Error::Password) => Ok(false),
        Err(e) => Err(e),
    }
}

/// A pre-computed Argon2 hash of a dummy password, used to perform a
/// constant-time "wasted" verify when the requested user does not exist,
/// preventing user-enumeration via response-time differences.
pub static DUMMY_HASH: &str = "$argon2id$\
    v=19$m=19456,t=2,p=1$\
    HfRKx+hpIQ18rfUQ5TuA5g$Zq2p1OruNc6cZAgJmgnTIs3XpBLKdrM/DujpWOPAMwQ"; // semgrep: ignore

