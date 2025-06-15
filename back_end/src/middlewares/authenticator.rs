use axum::{
    body::Body,
    extract::State,
    http::{self, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

use crate::jwt;
use crate::jwt::JwtError;
use crate::state::AppState;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Authorization header missing")]
    MissingAuthorizationHeader,

    #[error("Authorization token does NOT match")]
    InvalidAuthorizationToken,

    #[error("JWT token error: {0}")]
    JwtError(#[from] JwtError),

    #[error("Token has been revoked")]
    TokenRevoked,

    #[error("Internal Server Error")]
    InternalServerError,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        tracing::error!("{}", &self);        let status = match self {
            AuthError::MissingAuthorizationHeader => StatusCode::UNAUTHORIZED,
            AuthError::InvalidAuthorizationToken => StatusCode::UNAUTHORIZED,
            AuthError::JwtError(_) => StatusCode::UNAUTHORIZED,
            AuthError::TokenRevoked => StatusCode::UNAUTHORIZED,
            AuthError::InternalServerError => StatusCode::INTERNAL_SERVER_ERROR,
        };

        let body = Json(json!({
            "result": "error",
            "message": self.to_string()
        }));

        (status, body).into_response()
    }
}

/// Middleware function to authenticate JWT tokens.
/// If the token is valid, it allows the request to proceed.
/// If the token is invalid or missing, it returns an error response.
/// # Errors
/// Returns `AuthError` in the following cases:
/// - the authorization header is missing.
/// - the token is invalid.
/// - there is an error decoding the JWT token.
pub async fn auth(
    State(app_state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, AuthError> {
    let auth_header = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .ok_or(AuthError::MissingAuthorizationHeader)?;

    // Extract Bearer token
    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or(AuthError::InvalidAuthorizationToken)?;

    // Decode and validate JWT token
    let claims = jwt::decode_access_token(&app_state.config.jwt, token)?;

    tracing::debug!("JWT token validated: jti={}, username={}", claims.jti, claims.username);

    // Token is valid, proceed with the request
    Ok(next.run(req).await)
}
