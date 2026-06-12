use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::Request;
use axum::response::IntoResponse;
use axum::response::Response;
use chrono::Utc;
use serde::Serialize;

use crate::platform::api;
use crate::platform::assets;
use crate::platform::cookies;
use crate::platform::jwt;

use crate::platform::common::ArcContext;

pub fn create(context: ArcContext) -> Router {
    let public = Router::new()
        .route("/health", axum::routing::get(health_check))
        .with_state(context.clone());

    let api = Router::new()
        .merge(auth_router(context.clone()))
        .merge(users_router(context.clone()))
        .merge(app_router(context.clone()))
        .merge(public)
        .fallback(|| async { api::Error::not_found() });

    Router::new()
        .nest("/api", api)
        .fallback(assets::static_handler)
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(context)
}

fn app_router(ctx: ArcContext) -> axum::Router<ArcContext> {
    use crate::app;

    axum::Router::new()
        .merge(app::sample::api::router())
        .route_layer(axum::middleware::from_fn_with_state(ctx, auth_middleware))
}

fn users_router(ctx: ArcContext) -> axum::Router<ArcContext> {
    use crate::platform::identity::users;

    let users_service = users::Service::new(users::db::Repository, ctx.clone());
    axum::Router::new()
        .merge(users::api::router(users_service))
        .route_layer(axum::middleware::from_fn_with_state(ctx, auth_middleware))
}

fn auth_router(ctx: ArcContext) -> axum::Router<ArcContext> {
    use crate::platform::identity::auth;
    use crate::platform::identity::oauth;
    use crate::platform::identity::tokens;
    use crate::platform::identity::users;

    let auth_service = auth::Service::new(users::db::Repository, tokens::db::Repository, ctx.clone());
    let oauth_service = oauth::Service::new(ctx.clone(), auth_service.clone());
    axum::Router::new()
        .merge(auth::api::router(auth_service))
        .merge(oauth::api::router(oauth_service))
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

async fn auth_middleware(
    State(context): State<ArcContext>,
    mut req: Request<Body>,
    next: axum::middleware::Next,
) -> Result<Response, api::Error> {
    let claims = cookies::decode_access_token_from_cookie(&context.jwt, req.headers())?;
    req.extensions_mut().insert(claims);
    Ok(next.run(req).await)
}
