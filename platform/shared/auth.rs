use axum::body::Body;
use axum::extract::FromRequestParts;
use axum::extract::State;
use axum::http::Request;
use axum::http::request::Parts;
use axum::response::Response;

use crate::common::ApiError;
use crate::common::ArcContext;
use crate::internal::logger;
use crate::internal::tokens;
use crate::jwt;

pub fn check_oauth_config(config: &crate::config::OAuthSettings) {
    if let Err(error) = crate::identity::oauth::service::validate_google_config(config) {
        tracing::warn!("Google OAuth config is incomplete. {error}");
    }
}

pub async fn middleware(
    State(context): State<ArcContext>,
    mut req: Request<Body>,
    next: axum::middleware::Next,
) -> Result<Response, ApiError> {
    let claims = tokens::decode_token_from_req(&context, &req, jwt::TokenType::Access).map_err(|error| {
        logger::log_auth_rejection(&error);
        error.into_api_error()
    })?;

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
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts.extensions.get().cloned().ok_or(ApiError::invalid_token())
    }
}
