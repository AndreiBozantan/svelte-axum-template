use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::Request;
use axum::middleware;
use axum::middleware::Next;
use axum::response::Response;
use axum::routing::get;
use axum::routing::post;
use tower_http::trace::TraceLayer;

use crate::auth;
use crate::core;
use crate::routes;

/// Back end server built form various routes that are either public, require auth, or secure login
pub fn create_router(context: core::ArcContext) -> Router {
    // Create API routes that need ArcContext and auth middleware
    let api_routes = Router::new()
        .route("/api", get(routes::api::handler))
        .layer(middleware::from_fn_with_state(context.clone(), auth_middleware))
        .with_state(context.clone());

    // Create auth routes
    let auth_routes = Router::new()
        .route("/auth/login", post(routes::auth::login)) // sets username in session and returns JWT
        .route("/auth/logout", get(routes::auth::logout)) // deletes username in session and revokes tokens
        .route("/auth/refresh", post(routes::auth::refresh_access_token)) // refresh access token
        .route("/auth/revoke", post(routes::auth::revoke_token)) // revoke refresh token
        .route("/auth/oauth/google", get(routes::auth::google_auth_init)) // initiate Google OAuth
        .route("/auth/oauth/google/callback", get(routes::auth::google_auth_callback)) // Google OAuth callback
        .with_state(context.clone());

    let public_routes = Router::new()
        .route("/health", get(routes::health::health_check)) // Health check endpoint
        .with_state(context);

    // Combine all routes
    Router::new()
        .merge(auth_routes)
        .merge(api_routes)
        .merge(public_routes)
        .fallback(routes::assets::static_handler) // Serve static assets
        .layer(TraceLayer::new_for_http())
}

/// Middleware function to authenticate JWT tokens.
/// If the token is valid, it allows the request to proceed.
/// If the token is invalid or missing, it returns a `JwtError`.
async fn auth_middleware(
    State(context): State<core::ArcContext>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, auth::JwtError> {
    // Decode and validate JWT token
    let claims = auth::decode_access_token_from_req(&context.jwt, &req)?;

    tracing::info!(
        jti = claims.jti,
        username = claims.username,
        userid = claims.sub,
        exp = claims.exp,
        "JWT validated"
    );

    // Token is valid, proceed with the request
    Ok(next.run(req).await)
}
