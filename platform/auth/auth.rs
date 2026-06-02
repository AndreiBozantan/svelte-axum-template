use axum::body::Body;
use axum::extract::FromRequestParts;
use axum::extract::State;
use axum::http::Request;
use axum::http::request::Parts;
use axum::response::Response;

use crate::common::ApiError;
use crate::common::ArcContext;
use crate::common::AuthError;
use crate::jwt;
use crate::logger;
use crate::tokens;

pub async fn auth_middleware(
    State(context): State<ArcContext>,
    mut req: Request<Body>,
    next: axum::middleware::Next,
) -> Result<Response, AuthError> {
    let claims =
        tokens::decode_token_from_req(&context, &req, jwt::TokenType::Access).map_err(logger::log_auth_rejection)?;

    tracing::debug!(
        user_id = claims.sub,
        email = claims.email,
        tenant_id = ?claims.tenant_id,
        "Authenticated user accessing API"
    );

    req.extensions_mut().insert(claims);
    Ok(next.run(req).await)
}

// axum extractor — works only on routes behind auth_middleware
impl<S> FromRequestParts<S> for jwt::TokenClaims
where
    S: Send + Sync,
{
    type Rejection = ApiError;
    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts.extensions.get().cloned().ok_or_else(ApiError::not_authenticated)
    }
}
