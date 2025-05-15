use std::sync::Arc;

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

use crate::store::Store;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Authorization header missing")]
    MissingAuthorizationHeader,

    #[error("Invalid or expired token")]
    InvalidAuthorizationToken,

    #[error("Token validation error")]
    TokenValidationError,

    #[error("Internal Server Error")]
    InternalServerError,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        tracing::error!("{}", &self);

        let status = match self {
            AuthError::MissingAuthorizationHeader => StatusCode::UNAUTHORIZED,
            AuthError::InvalidAuthorizationToken => StatusCode::UNAUTHORIZED,
            AuthError::TokenValidationError => StatusCode::UNAUTHORIZED,
            AuthError::InternalServerError => StatusCode::INTERNAL_SERVER_ERROR,
        };

        let body = Json(json!({
            "result": "error",
            "message": self.to_string()
        }));

        (status, body).into_response()
    }
}

/// middleware function to authenticate authorization token
/// check store that contains token and see if it matches authorization header starting with "Bearer"
/// used example in axum docs on middleware <https://docs.rs/axum/latest/axum/middleware/index.html>
///
/// Returns Error's in JSON format.
#[allow(clippy::missing_errors_doc)]
pub async fn auth(
    State(store): State<Arc<Store>>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, AuthError> {
    let auth_header = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .ok_or(AuthError::MissingAuthorizationHeader)?;

    tracing::debug!("Received Authorization Header: {}", auth_header);    // Use the async token check for more comprehensive validation
    match store.api_token_check_async(auth_header).await {
        Ok(true) => {
            tracing::debug!("Token validation successful");
            Ok(next.run(req).await)
        },
        Ok(false) => {
            tracing::warn!("Invalid or expired token");
            Err(AuthError::InvalidAuthorizationToken)
        },
        Err(e) => {
            tracing::error!("Token validation error: {:?}", e);
            Err(AuthError::TokenValidationError)
        },
    }
}
