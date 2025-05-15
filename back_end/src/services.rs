use axum::{
    middleware,
    routing::{get, post, patch},
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
    // Routes that don't need state
    let stateless_routes = Router::new()
        .route("/auth/session", get(routes::session::data_handler))
        .route("/auth/logout", get(routes::logout))
        .route("/test", get(routes::not_implemented_route));
        
    // Routes that need state
    let stateful_routes = Router::new()
        .route("/auth/login", post(routes::login))
        .route("/auth/token/refresh", post(routes::refresh_token))
        .route("/auth/token/revoke", post(routes::revoke_token))
        .with_state(shared_state.clone());
    
    // Secured routes
    let auth_routes = back_auth_route();
      // API routes with token authentication
    let api_routes = back_user_routes(shared_state.clone())
        .merge(back_token_route(shared_state));

    // Create the final router with all routes
    Router::new()
        .merge(front_public_route())
        .merge(stateless_routes)
        .merge(stateful_routes)
        .merge(auth_routes)
        .merge(api_routes)
        .layer(session_layer)
}

// Add user routes with state separately
pub fn back_user_routes<S>(state: Arc<Store>) -> Router<S> {
    Router::new()
        .route("/users", post(routes::create_user)) // create a new user
        .route("/users/:id", get(routes::get_user)) // get user by ID
        .route("/users/:id", patch(routes::update_user)) // update user
        .with_state(state)
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
