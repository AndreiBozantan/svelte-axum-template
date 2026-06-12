use axum::Router;
use axum::extract::State;
use axum::response::IntoResponse;
use chrono::Utc;
use serde::Serialize;

use crate::platform::api;
use crate::platform::auth;
use crate::platform::assets;
use crate::platform::common::ArcContext;

pub fn create(context: ArcContext) -> Router {
    let public = Router::new()
        .route("/health", axum::routing::get(health_check))
        .with_state(context.clone());

    let api = Router::new()
        .merge(identity_router(context.clone()))
        .merge(app_router(context.clone()))
        .merge(public)
        .fallback(|| async { api::Error::not_found() });

    Router::new()
        .nest("/api", api)
        .fallback(assets::static_handler)
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(context)
}

pub fn app_router(ctx: ArcContext) -> axum::Router<ArcContext> {
    use crate::app;

    axum::Router::new()
        .merge(app::sample::api::router())
        .route_layer(axum::middleware::from_fn_with_state(
            ctx,
            auth::middleware,
        ))
}

pub fn identity_router(ctx: ArcContext) -> axum::Router<ArcContext> {
    use crate::platform::identity::auth;
    use crate::platform::identity::oauth;
    use crate::platform::identity::tokens;
    use crate::platform::identity::users;

    let auth_service = auth::Service::new(users::db::Repository, tokens::db::Repository, ctx.clone());
    let oauth_service = oauth::Service::new(ctx.clone(), auth_service.clone());
    let users_service = users::Service::new(users::db::Repository, ctx);

    axum::Router::new()
        .merge(auth::api::router(auth_service))
        .merge(oauth::api::router(oauth_service))
        .merge(users::api::router(users_service))
}

#[derive(Serialize)]
struct HealthCheckResponse {
    message: String,
    time: String,
}

#[allow(clippy::unused_async)]
async fn health_check(State(context): State<ArcContext>) -> Result<impl IntoResponse, api::Error> {
    sqlx::query("SELECT 1").execute(&context.db).await.map_err(|error| {
        tracing::error!("Health check database ping failed: {error}");
        api::Error::internal()
    })?;

    Ok(axum::Json(HealthCheckResponse {
        message: "server and database are up and running".to_string(),
        time: Utc::now().to_rfc3339(),
    }))
}
