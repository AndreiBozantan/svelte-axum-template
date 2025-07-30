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
use crate::middleware::rate_limit;
use crate::routes;

/// Back end server built form various routes that are either public, require auth, or secure login
pub fn create_router(context: core::ArcContext) -> Router {
    // Create API routes that need ArcContext and auth middleware
    let api_routes = Router::new()
        .route("/api", get(routes::api::handler))
        .layer(middleware::from_fn_with_state(context.clone(), auth_middleware))
        .with_state(context.clone());

    // Create auth routes with rate limiting for OAuth endpoints
    let auth_routes = Router::new()
        .route("/auth/login", post(routes::auth::login)) // sets username in session and returns JWT
        .route("/auth/logout", get(routes::auth::logout)) // deletes username in session and revokes tokens
        .route("/auth/refresh", post(routes::auth::refresh_access_token)) // refresh access token
        .route("/auth/revoke", post(routes::auth::revoke_token)) // revoke refresh token
        .route("/auth/oauth/google", get(routes::auth::google_auth_init)) // initiate Google OAuth
        .route("/auth/oauth/google/callback", get(routes::auth::google_auth_callback)) // Google OAuth callback
        .layer(axum::middleware::from_fn(rate_limit::oauth_rate_limit_middleware))
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

async fn auth_middleware(
    State(context): State<core::ArcContext>,
    req: Request<Body>,
    next: Next,
) -> Response {
    match auth::decode_access_token_from_req(&context.jwt, &req) {
        Ok(claims) => {
            tracing::debug!(
                user_id = claims.sub,
                username = claims.username,
                tenant_id = ?claims.tenant_id,
                "Authenticated user accessing API"
            );
            next.run(req).await
        }
        Err(e) => {
            tracing::warn!("Unauthorized access attempt: {}", e);
            let mut response = Response::new(axum::body::Body::from("Unauthorized"));
            *response.status_mut() = axum::http::StatusCode::UNAUTHORIZED;
            response
        }
    }
}
