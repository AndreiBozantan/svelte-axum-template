use axum::Router;
use axum::body::Body;
use axum::extract::FromRequestParts;
use axum::extract::State;
use axum::http::Request;
use axum::http::StatusCode;
use axum::http::request::Parts;
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
    // create auth routes 
    let auth = Router::new()
        .route("/login", post(routes::auth::login))
        .route("/logout", post(routes::auth::logout))
        .route("/user_info", get(routes::auth::user_info))
        .route("/refresh", post(routes::auth::refresh));

    // create oauth routes with rate limiting 
    let oauth = Router::new()
        .route("/google", get(routes::auth::google_auth_init))
        .route("/google/callback", get(routes::auth::google_auth_callback))
        .layer(axum::middleware::from_fn(middleware::oauth_rate_limit_middleware));

    // protected API routes that need ArcContext and auth middleware
    let protected = Router::new()
        .route("/test", get(routes::api::test_handler))
        .layer(axum::middleware::from_fn_with_state(context.clone(), auth_middleware));

    // public API routes
    let public = Router::new()
        .route("/health", get(routes::health::health_check));

    let api = Router::new()
        .nest("/auth", auth)
        .nest("/oauth", oauth)
        .merge(protected)
        .merge(public)
        .fallback(|| async {
            (
                axum::http::StatusCode::NOT_FOUND,
                axum::Json(serde_json::json!({"result": "error", "message": "not found"})),
            )
        });

    // combine all routes
    Router::new()
        .nest("/api", api)
        .route("/user_info.js", get(routes::user_info::user_info_handler))
        .fallback(routes::assets::static_handler) // serve static assets
        .with_state(context)
        .layer(TraceLayer::new_for_http()) // add http request tracing for all routes
}

async fn auth_middleware(
    State(context): State<core::ArcContext>,
    mut req: Request<Body>,
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

    req.extensions_mut().insert(claims);
    Ok(next.run(req).await)
}

// axum extractor — works only on routes behind auth_middleware
impl<S> FromRequestParts<S> for auth::TokenClaims
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, axum::Json<serde_json::Value>);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts.extensions.get().cloned().ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                axum::Json(serde_json::json!({
                    "result": "error",
                    "message": "missing auth claims"
                })),
            )
        })
    }
}
