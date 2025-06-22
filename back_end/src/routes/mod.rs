mod assets;
mod auth;
mod api;
mod health;

use axum::body::Body;
use axum::extract::State;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::Response;
use axum::middleware;
use axum::routing::get;
use axum::routing::post;
use axum::Router;
use tower_http::trace::TraceLayer;

use crate::app;
use crate::auth::jwt;
use crate::auth::jwt::JwtError;

/// Back end server built form various routes that are either public, require auth, or secure login
pub fn create_router(context: app::Context) -> Router {
    // Create API routes that need AppState and auth middleware
    let api_routes = Router::new()
        .layer(middleware::from_fn_with_state(context.clone(), auth_middleware))
        .route("/api", get(api::handler))
        .with_state(context.clone());

    // Create auth routes
    let auth_routes = Router::new()
        .route("/auth/login", post(auth::login)) // sets username in session and returns JWT
        .route("/auth/logout", get(auth::logout)) // deletes username in session and revokes tokens
        .route("/auth/refresh", post(auth::refresh_access_token)) // refresh access token
        .route("/auth/revoke", post(auth::revoke_token)) // revoke refresh token
        .route("/health", get(health::health_check)) // Health check endpoint
        .with_state(context);

    // Combine all routes
    Router::new()
        .merge(auth_routes)
        .merge(api_routes)
        .fallback(assets::static_handler)
        .layer(TraceLayer::new_for_http())
}

/// Middleware function to authenticate JWT tokens.
/// If the token is valid, it allows the request to proceed.
/// If the token is invalid or missing, it JwtError.
async fn auth_middleware(
    State(context): State<app::Context>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, JwtError> {
    // Decode and validate JWT token
    let claims = jwt::decode_access_token_from_req(&context.config.jwt, &req)?;

    tracing::info!(
        jti = claims.jti,
        username = claims.username,
        userid = claims.sub,
        exp = claims.exp,
        "JWT validated");

    // Token is valid, proceed with the request
    Ok(next.run(req).await)
}
