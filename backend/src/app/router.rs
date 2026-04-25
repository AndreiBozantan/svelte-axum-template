use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::Request;
use axum::response::Response;
use axum::routing::get;
use axum::routing::post;
use tower_http::trace::TraceLayer;

use crate::auth;
use crate::core;
use crate::middleware;
use crate::routes;

/// Back end server built form various routes that are either public, require auth, or secure login
pub fn create_router(context: core::ArcContext) -> Router {
    // create auth routes with rate limiting for OAuth endpoints
    let auth_routes = Router::new()
        .route("/login", post(routes::auth::login)) // sets username in session and returns JWT
        .route("/logout", get(routes::auth::logout)) // deletes username in session and revokes tokens
        .route("/user_info", get(routes::auth::user_info)) // check session status
        .route("/refresh", post(routes::auth::refresh_access_token)) // refresh access token
        .route("/refresh/revoke", post(routes::auth::revoke_refresh_token)) // revoke refresh token
        .route("/oauth/google", get(routes::auth::google_auth_init)) // initiate Google OAuth
        .route("/oauth/google/callback", get(routes::auth::google_auth_callback)) // Google OAuth callback
        .layer(axum::middleware::from_fn(middleware::oauth_rate_limit_middleware))
        .with_state(context.clone());

    // protected API routes that need ArcContext and auth middleware
    let protected_api_routes = Router::new()
        .route("/test", get(routes::api::test_handler))
        .layer(axum::middleware::from_fn_with_state(context.clone(), auth_middleware))
        .with_state(context.clone());

    // public API routes
    let public_routes = Router::new()
        .route("/health", get(routes::health::health_check)) // health check endpoint
        .with_state(context.clone());

    let api_router = Router::new()
        .nest("/auth", auth_routes)
        .merge(protected_api_routes)
        .merge(public_routes)
        .fallback(|| async {
            (
                axum::http::StatusCode::NOT_FOUND,
                axum::Json(serde_json::json!({"result": "error", "message": "not found"})),
            )
        });

    // combine all routes
    Router::new()
        .nest("/api", api_router)
        .route("/user_info.js", get(routes::user_info::user_info_handler))
        .fallback(routes::assets::static_handler) // serve static assets
        .with_state(context)
        .layer(TraceLayer::new_for_http()) // add http request tracing for all routes
    }
async fn auth_middleware(
    State(context): State<core::ArcContext>,
    req: Request<Body>,
    next: axum::middleware::Next,
) -> Result<Response, auth::AuthError> {
    let claims =
        auth::decode_token_from_req(&context, &req, auth::TokenType::Access).map_err(auth::log_auth_rejection)?;
    tracing::debug!(
        user_id = claims.sub,
        email = claims.email,
        tenant_id = ?claims.tenant_id,
        "Authenticated user accessing API"
    );
    Ok(next.run(req).await)
}
