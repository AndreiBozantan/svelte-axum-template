use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::Json;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use thiserror::Error;

use crate::jwt;
use crate::jwt::JwtError;
use crate::state::AppState;

#[derive(Debug, Error)]
pub enum AuthMiddlewareError {
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

impl IntoResponse for AuthMiddlewareError {
    fn into_response(self) -> axum::response::Response {
        tracing::error!(
            error_type = %std::any::type_name::<Self>(),
            error_subtype = %std::any::type_name_of_val(&self),
            error_message = %self);

        let status = match self {
            AuthMiddlewareError::MissingAuthorizationHeader => StatusCode::UNAUTHORIZED,
            AuthMiddlewareError::InvalidAuthorizationToken => StatusCode::UNAUTHORIZED,
            AuthMiddlewareError::JwtError(_) => StatusCode::UNAUTHORIZED,
            AuthMiddlewareError::TokenRevoked => StatusCode::UNAUTHORIZED,
            AuthMiddlewareError::InternalServerError => StatusCode::INTERNAL_SERVER_ERROR,
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
) -> Result<Response, AuthMiddlewareError> {
    // Decode and validate JWT token
    let claims = jwt::decode_access_token_from_req(&app_state.config.jwt, &req)?;

    tracing::info!(
        jti = claims.jti,
        username = claims.username,
        userid = claims.sub,
        exp = claims.exp,
        "JWT validated");

    // Token is valid, proceed with the request
    Ok(next.run(req).await)
}
