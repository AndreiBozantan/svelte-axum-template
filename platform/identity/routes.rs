use axum::Router;
use axum::routing::get;
use axum::routing::post;

use crate::auth::auth_middleware;
use crate::common::ArcContext;

use super::api;

fn auth() -> Router<ArcContext> {
    Router::new()
        .route("/auth/login", post(api::login))
        .route("/auth/logout", post(api::logout))
        .route("/auth/refresh", post(api::refresh))
}

fn oauth() -> Router<ArcContext> {
    Router::new()
        .route("/oauth/google", get(api::google_auth_init))
        .route("/oauth/google/callback", get(api::google_auth_callback))
}

fn users(ctx: ArcContext) -> Router<ArcContext> {
    Router::new()
        .route("/users", get(api::list_users))
        .route("/users/me", get(api::user_info))
        .route_layer(axum::middleware::from_fn_with_state(ctx, auth_middleware))
}

pub fn create(ctx: ArcContext) -> Router<ArcContext> {
    Router::new().merge(auth()).merge(oauth()).merge(users(ctx))
}
