use axum::Router;
use axum::routing::get;
use axum::routing::post;

use crate::auth::auth_middleware;
use crate::common::ArcContext;
use crate::handlers;

fn auth() -> Router<ArcContext> {
    Router::new()
        .route("/auth/login",   post(handlers::login))
        .route("/auth/logout",  post(handlers::logout))
        .route("/auth/refresh", post(handlers::refresh))
}

fn oauth() -> Router<ArcContext> {
    Router::new()
        .route("/oauth/google",           get(handlers::google_auth_init))
        .route("/oauth/google/callback",  get(handlers::google_auth_callback))
}

fn users(ctx: ArcContext) -> Router<ArcContext> {
    Router::new()
        .route("/users",    get(handlers::list_users))
        .route("/users/me", get(handlers::user_info))
        .route_layer(axum::middleware::from_fn_with_state(ctx, auth_middleware))
}

pub fn create(ctx: ArcContext) -> Router<ArcContext> {
    Router::new()
        .merge(auth())
        .merge(oauth())
        .merge(users(ctx))
}
