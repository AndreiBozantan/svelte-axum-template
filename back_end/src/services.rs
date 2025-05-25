use axum::{
    middleware,
    routing::{get, post},
    Router,
};
use tower_http::trace::TraceLayer;
use tower_sessions::{SessionManagerLayer, SessionStore};

use crate::{
    assets,
    middlewares, routes,
    state::AppState,
};

// *********
// FRONT END
// *********
// Front end to serve svelte build bundle from embedded assets in the binary
pub fn front_public_route() -> Router {
    Router::new()
        .fallback(assets::static_handler)
        .layer(TraceLayer::new_for_http())
}

// ********
// BACK END
// ********
// Back end server built form various routes that are either public, require auth, or secure login
pub fn backend<S: SessionStore + Clone + Send + Sync + 'static>(
    session_layer: SessionManagerLayer<S>,
    app_state: AppState,
) -> Router {
    // Create auth routes that need AppState
    let auth_routes = Router::new()
        .route("/auth/session", get(routes::session::data_handler)) // gets session data
        .route("/auth/login", post(routes::login)) // sets username in session and returns JWT
        .route("/auth/logout", get(routes::logout)) // deletes username in session and revokes tokens
        .route("/auth/refresh", post(routes::refresh_token)) // refresh access token
        .route("/auth/revoke", post(routes::revoke_token)) // revoke refresh token
        .with_state(app_state.clone());    // Create API routes that need AppState and auth middleware
    let api_routes = Router::new()
        .route("/api", get(routes::api::handler))
        .layer(middleware::from_fn_with_state(app_state.clone(), middlewares::auth));

    // Create session routes
    let session_routes = Router::new()
        .route("/secure", get(routes::session::handler))
        .route_layer(middleware::from_fn(middlewares::user_secure));    // Combine all routes
    Router::new()
        .merge(auth_routes)
        .merge(api_routes)
        .merge(session_routes)
        .route("/test", get(routes::not_implemented_route))
        .layer(session_layer)
}
