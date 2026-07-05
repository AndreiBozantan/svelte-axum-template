use axum::body::Body;
use axum::extract::State;
use axum::http::Request;
use axum::response::IntoResponse;
use axum::response::Response;
use chrono::Utc;
use serde::Deserialize;
use serde::Serialize;
use tracing::error;
use tracing::info;
use utoipax::router::OpenApiRouter;

use crate::platform::api;
use crate::platform::assets;
use crate::platform::cookies;
use crate::platform::rate_limiter;

use crate::platform::common::ArcContext;

#[derive(Clone)]
struct CustomPanicHandler;

pub fn create(context: ArcContext) -> OpenApiRouter {
    use crate::app;
    use crate::platform::identity::auth;
    use crate::platform::identity::oauth;
    use crate::platform::identity::tokens;
    use crate::platform::identity::users;

    rate_limiter::TRUSTED_PROXY.store(
        context.settings.server.trusted_proxy,
        std::sync::atomic::Ordering::Relaxed,
    );

    let auth_service = auth::Service::new(users::db::Repository, tokens::db::Repository, context.clone());
    let oauth_service = oauth::Service::new(context.clone(), auth_service.clone());
    let users_service = users::Service::new(users::db::Repository, context.clone());

    // unauthenticated routes setup
    let public_router = OpenApiRouter::new()
        .merge(auth::api::router(auth_service))
        .merge(oauth::api::router(oauth_service))
        .merge(OpenApiRouter::new().routes(utoipax::routes!(health_check)))
        .with_state(context.clone());

    // authenticated routes setup
    let private_router = OpenApiRouter::new()
        .merge(users::api::router(users_service))
        .merge(app::sample::api::router())
        .route_layer(axum::middleware::from_fn_with_state(context.clone(), auth_middleware));

    // merge routers and specify fallback for unmatched /api routes
    let api = OpenApiRouter::new()
        .merge(public_router)
        .merge(private_router)
        .fallback(|| async { api::Error::not_found() });

    let router = OpenApiRouter::new().nest("/api", api).fallback(assets::static_handler);
    let router = rate_limiter::add_global_rate_limiting(router, &context.settings.rate_limiter.global);

    router
        .layer(
            tower_http::trace::TraceLayer::new_for_http().make_span_with(|request: &Request<Body>| {
                let client_ip = rate_limiter::extract_client_ip(request);
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
        // the timeout layer sits inside the security-headers layer so that
        // timeout responses also carry the security headers
        .layer(axum::middleware::from_fn(timeout_middleware))
        .layer(axum::middleware::from_fn(security_headers_middleware))
        .layer(axum::extract::DefaultBodyLimit::max(2 * 1024 * 1024))
        .with_state(context)
}

pub fn add_swagger(router: OpenApiRouter) -> axum::Router {
    #[cfg(feature = "swagger")]
    {
        let (router, openapi) = router.split_for_parts();
        router.merge(utoipa_swagger_ui::SwaggerUi::new("/docs").url("/openapi.json", openapi))
    }
    #[cfg(not(feature = "swagger"))]
    router.split_for_parts().0
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

#[derive(Serialize, utoipa::ToSchema)]
pub struct HealthCheckResponse {
    pub message: String,
    pub time: String,
}

#[derive(Deserialize, utoipa::ToSchema, utoipa::IntoParams)]
pub struct HealthCheckQuery {
    #[serde(default)]
    pub panic: bool,
}

#[allow(clippy::unused_async)]
#[utoipa::path(
    get,
    path = "/health",
    params(
        HealthCheckQuery
    ),
    responses(
        (status = 200, description = "Health check successful", body = HealthCheckResponse),
        (status = 500, description = "Database or server unhealthy", body = api::Error)
    )
)]
async fn health_check(
    State(context): State<ArcContext>,
    query: api::Query<HealthCheckQuery>,
) -> Result<impl IntoResponse, api::Error> {
    sqlx::query("SELECT 1").execute(&context.db).await.map_err(|error| {
        error!(%error, "health_check_failed");
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
                info!(HEALTHY_PANIC_MESSAGE);
            },
            Some(message) => {
                error!(error = %message, "server panic occurred");
            },
            None => {
                error!(error = "unknown_panic", "server panic occurred");
            },
        }

        api::Error::internal().into_response()
    }
}

fn extract_user_agent(req: &Request<Body>) -> Option<String> {
    req.headers()
        .get("user-agent")
        .and_then(|ua| ua.to_str().ok())
        .map(std::string::ToString::to_string)
}

const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

async fn timeout_middleware(
    req: Request<Body>,
    next: axum::middleware::Next,
) -> Response {
    tokio::time::timeout(REQUEST_TIMEOUT, next.run(req))
        .await
        .unwrap_or_else(|_| api::Error::request_timeout().into_response())
}

async fn security_headers_middleware(
    req: Request<Body>,
    next: axum::middleware::Next,
) -> Response {
    let mut res = next.run(req).await;
    let headers = res.headers_mut();

    headers.insert(
        axum::http::header::X_CONTENT_TYPE_OPTIONS,
        axum::http::HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        axum::http::header::X_FRAME_OPTIONS,
        axum::http::HeaderValue::from_static("DENY"),
    );
    headers.insert(
        axum::http::header::REFERRER_POLICY,
        axum::http::HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    headers.insert(
        axum::http::header::CONTENT_SECURITY_POLICY,
        axum::http::HeaderValue::from_static(
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; frame-ancestors 'none';",
        ),
    );
    headers.insert(
        axum::http::header::STRICT_TRANSPORT_SECURITY,
        axum::http::HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );
    headers.insert(
        axum::http::header::HeaderName::from_static("permissions-policy"),
        axum::http::HeaderValue::from_static("geolocation=(), microphone=(), camera=()"),
    );

    res
}
