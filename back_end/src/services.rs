use axum::{
    middleware,
    routing::{get, post},
    Router,
};
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use tower_sessions::{SessionManagerLayer, SessionStore};

use crate::{
    assets,
    middlewares, routes,
    store::{self, Store},
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
    shared_state: Arc<store::Store>,
) -> Router {
    // Create the backend routes
    Router::new()
        .merge(back_public_route())
        .merge(back_auth_route())
        .merge(back_token_route(shared_state))
        // In axum 0.8.4, we add the session layer
        .with_state(())
        .layer(session_layer)
}

// *********
// BACKEND NON-AUTH
// *********
//
pub fn back_public_route() -> Router {
    Router::new()
        .route("/auth/session", get(routes::session::data_handler)) // gets session data
        .route("/auth/login", post(routes::login)) // sets username in session
        .route("/auth/logout", get(routes::logout)) // deletes username in session
        .route("/test", get(routes::not_implemented_route))
}

// *********
// BACKEND SESSION
// *********
//
pub fn back_auth_route() -> Router {
    Router::new()
        .route("/secure", get(routes::session::handler))
        .route_layer(middleware::from_fn(middlewares::user_secure))
}

// *********
// BACKEND API
// *********
//
//
// invoked with State that stores API that is checked by the `middleware::auth`
pub fn back_token_route<S>(state: Arc<Store>) -> Router<S> {
    Router::new()
        .route("/api", get(routes::api::handler))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            middlewares::auth,
        ))
        .with_state(state)
}
