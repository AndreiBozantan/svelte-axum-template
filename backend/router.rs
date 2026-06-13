use std::net::SocketAddr;

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::Request;
use axum::response::IntoResponse;
use axum::response::Response;
use chrono::Utc;
use serde::Deserialize;
use serde::Serialize;

use crate::platform::api;
use crate::platform::assets;
use crate::platform::cookies;
use crate::platform::logger::*;

use crate::platform::common::ArcContext;

#[derive(Clone)]
struct CustomPanicHandler;

pub fn create(context: ArcContext) -> Router {
    let api = Router::new()
        .merge(auth_router(&context))
        .merge(users_router(&context))
        .merge(app_router(&context))
        .merge(public_router(&context))
        .fallback(|| async { api::Error::not_found() });

    Router::new()
        .nest("/api", api)
        .fallback(assets::static_handler)
        .layer(
            tower_http::trace::TraceLayer::new_for_http().make_span_with(|request: &Request<Body>| {
                let client_ip = extract_client_ip(request);
                let user_agent = extract_user_agent(request);
                tracing::info_span!(
                    "request",
                    method = %request.method(),
                    uri = %request.uri(),
                    version = ?request.version(),
                    client_ip = %client_ip,
                    user_agent = user_agent,
                )
            }),
        )
        .layer(tower_http::catch_panic::CatchPanicLayer::custom(CustomPanicHandler))
        .with_state(context)
}

fn public_router(context: &ArcContext) -> axum::Router<ArcContext> {
    Router::new()
        .route("/health", axum::routing::get(health_check))
        .with_state(context.clone())
}

fn app_router(context: &ArcContext) -> axum::Router<ArcContext> {
    use crate::app;

    axum::Router::new()
        .merge(app::sample::api::router())
        .route_layer(axum::middleware::from_fn_with_state(context.clone(), auth_middleware))
}

fn users_router(context: &ArcContext) -> axum::Router<ArcContext> {
    use crate::platform::identity::users;

    let users_service = users::Service::new(users::db::Repository, context.clone());
    axum::Router::new()
        .merge(users::api::router(users_service))
        .route_layer(axum::middleware::from_fn_with_state(context.clone(), auth_middleware))
}

fn auth_router(context: &ArcContext) -> axum::Router<ArcContext> {
    use crate::platform::identity::auth;
    use crate::platform::identity::oauth;
    use crate::platform::identity::tokens;
    use crate::platform::identity::users;

    let auth_service = auth::Service::new(users::db::Repository, tokens::db::Repository, context.clone());
    let oauth_service = oauth::Service::new(context.clone(), auth_service.clone());
    axum::Router::new()
        .merge(auth::api::router(auth_service))
        .merge(oauth::api::router(oauth_service))
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

#[derive(Serialize)]
struct HealthCheckResponse {
    message: String,
    time: String,
}

#[derive(Deserialize)]
struct HealthCheckQuery {
    #[serde(default)]
    panic: bool,
}

#[allow(clippy::unused_async)]
async fn health_check(
    State(context): State<ArcContext>,
    query: api::Query<HealthCheckQuery>,
) -> Result<impl IntoResponse, api::Error> {
    sqlx::query("SELECT 1").execute(&context.db).await.map_err(|error| {
        log_error!("router", "health_check", error);
        api::Error::internal()
    })?;

    let api::Query(query) = query;
    if query.panic {
        healthy_panic();
    }

    Ok(axum::Json(HealthCheckResponse {
        message: "server and database are up and running".to_string(),
        time: Utc::now().to_rfc3339(),
    }))
}

const HEALTHY_PANIC_MESSAGE: &str = "simulating a runtime crash! don't panic!";

fn healthy_panic() {
    panic!("{HEALTHY_PANIC_MESSAGE}");
}

impl tower_http::catch_panic::ResponseForPanic for CustomPanicHandler {
    type ResponseBody = Body;

    fn response_for_panic(
        &mut self,
        err: Box<dyn std::any::Any + Send + 'static>,
    ) -> Response<Self::ResponseBody> {
        let panic_message = err
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| err.downcast_ref::<String>().map(String::as_str));

        match panic_message {
            Some(HEALTHY_PANIC_MESSAGE) => {
                log_info!("router", "panic", details = HEALTHY_PANIC_MESSAGE);
            },
            Some(message) => {
                log_error!("router", "panic", message);
            },
            None => {
                log_error!("router", "panic", "unknown_payload");
            },
        }

        api::Error::internal().into_response()
    }
}

fn extract_client_ip(req: &Request<Body>) -> String {
    // check common proxy headers
    if let Some(forwarded_for) = req.headers().get("x-forwarded-for")
        && let Ok(value) = forwarded_for.to_str()
        && let Some(ip) = value.split(',').next()
    {
        return ip.trim().to_string();
    }

    if let Some(real_ip) = req.headers().get("x-real-ip")
        && let Ok(value) = real_ip.to_str()
    {
        return value.to_string();
    }

    // fallback to Axum's SocketAddr ConnectInfo
    if let Some(axum::extract::ConnectInfo(addr)) = req.extensions().get::<axum::extract::ConnectInfo<SocketAddr>>() {
        return addr.ip().to_string();
    }

    "unknown".to_string()
}

fn extract_user_agent(req: &Request<Body>) -> Option<String> {
    req.headers()
        .get("user-agent")
        .and_then(|ua| ua.to_str().ok())
        .map(std::string::ToString::to_string)
}
