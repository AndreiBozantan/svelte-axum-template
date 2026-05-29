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

use crate::platform::common::ArcContext;
use crate::platform::common::AuthError;
use crate::platform::jwt;
use crate::platform::logger;
use crate::platform::tokens;
use crate::platform::assets;

use crate::app::identity::identity_api;
use crate::app::system::system_api;

/// Back end server built form various routes that are either public, require auth, or secure login
pub fn create_router(context: ArcContext) -> Router {
    // create auth routes
    let auth = Router::new()
        .route("/login", post(identity_api::login))
        .route("/logout", post(identity_api::logout))
        .route("/refresh", post(identity_api::refresh));

    // create oauth routes with rate limiting
    let oauth = Router::new()
        .route("/google", get(identity_api::google_auth_init))
        .route("/google/callback", get(identity_api::google_auth_callback));

    // protected API routes that need ArcContext and auth middleware
    let protected = Router::new()
        .route("/users", get(identity_api::list_users))
        .route("/users/me", get(identity_api::user_info))
        .layer(axum::middleware::from_fn_with_state(context.clone(), auth_middleware));

    // public API routes
    let public = Router::new().route("/health", get(system_api::health_check));

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
        .fallback(assets::static_handler) // serve static assets
        .with_state(context)
        .layer(TraceLayer::new_for_http()) // add http request tracing for all routes
}

async fn auth_middleware(
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
