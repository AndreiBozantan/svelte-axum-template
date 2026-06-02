use axum::Router;
use axum::extract::State;
use axum::response::IntoResponse;
use std::error::Error;
use std::net::SocketAddr;

use serde::Serialize;
use thiserror::Error;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use platform::common;
use platform::common::ApiError;
use platform::common::ArcContext;
use platform::config;
use platform::db;
use platform::jwt;
use platform::migrations;
use platform::sso;

use crate::cli;

/// Application-level error type
#[derive(Debug, Error)]
pub enum AppError {
    #[error("Configuration error: {0}")]
    ConfigLoadingFailed(#[from] ::config::ConfigError),

    #[error("Database error: {0}")]
    DatabaseOperationFailed(#[from] db::SqlError),

    #[error("JWT error: {0}")]
    JwtOperationFailed(#[from] jwt::JwtError),

    #[error("Migration error: {0}")]
    MigrationFailed(#[from] migrations::MigrationError),

    #[error("CLI error: {0}")]
    CliOperationFailed(#[from] cli::CliError),

    #[error("Network address parsing error: {0}")]
    AddressParsingFailed(#[from] std::net::AddrParseError),

    #[error("Server error: {0}")]
    ServerStartingFailed(#[from] std::io::Error),

    #[error("Server error: {0}")]
    HttpClientCreationFailed(#[from] reqwest::Error),
}

pub async fn run() {
    if let Err(e) = run_app().await {
        eprintln!("❌ {e}\n");

        let mut source = e.source();
        while let Some(err) = source {
            eprintln!("Caused by: {err}");
            source = err.source();
        }

        let backtrace = std::backtrace::Backtrace::capture();
        eprintln!("{backtrace}");

        std::process::exit(1);
    }
}

async fn run_app() -> Result<(), AppError> {
    let settings = config::AppSettings::new()?;
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(&settings.server.log_directives))
        .with(tracing_subscriber::fmt::layer())
        .init();

    sso::check_oauth_config(&settings.oauth);

    let http_client = create_http_client()?;
    let db = db::create_context(&settings.database).await?;
    let jwt_secret = jwt::get_jwt_secret()?;
    let jwt = jwt::JwtContext::new(&settings.jwt, &jwt_secret)?;
    let ctx = common::Context::new(db, jwt, settings, http_client).into();
    if !cli::run_cli(&ctx).await? {
        migrations::run_migrations(&ctx).await?;
        start_server(ctx).await?;
    }
    Ok(())
}

async fn start_server(ctx: common::ArcContext) -> Result<(), AppError> {
    let addr = ctx.settings.get_server_address().parse::<SocketAddr>()?;
    let router = create_router(ctx.clone()).into_make_service_with_connect_info::<SocketAddr>();
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("starting server... 🚀 ");
    tracing::info!("app_env: {}", ctx.env);
    tracing::info!("logging: {}", ctx.settings.server.log_directives);
    tracing::info!("cfg_dir: {}", config::AppSettings::get_config_full_path());
    tracing::info!("address: http://{}", addr);
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

fn create_http_client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
}

/// Tokio signal handler that will wait for a user to press CTRL+C.
/// We use this in our `Server` method `with_graceful_shutdown`.
async fn shutdown_signal() {
    match tokio::signal::ctrl_c().await {
        Ok(()) => tracing::info!("Shutdown signal received, shutting down gracefully"),
        Err(e) => tracing::error!("Failed to listen for shutdown signal: {}", e),
    }
}

#[derive(Serialize)]
struct HealthCheckResponse {
    message: String,
    time: String,
}

#[allow(clippy::unused_async)]
pub async fn health_check(State(context): State<ArcContext>) -> Result<impl IntoResponse, ApiError> {
    platform::identity::queries::get_tenant_by_id(&context.db, 0)
        .await
        .map_err(|e| {
            tracing::error!("Health check failed to read default tenant from database: {}", e);
            ApiError::internal()
        })?;
    let body = HealthCheckResponse {
        message: "server and database are up and running".to_string(),
        time: chrono::Utc::now().to_rfc3339(),
    };
    Ok(axum::response::Json(body))
}

pub fn create_router(context: ArcContext) -> Router {
    let public = Router::new()
        .route("/health", axum::routing::get(health_check))
        .with_state(context.clone());

    let api = Router::new()
        .merge(platform::identity::routes::create(context.clone()))
        .merge(public)
        .fallback(|| async { ApiError::not_found() });

    Router::new()
        .nest("/api", api)
        .fallback(platform::assets::static_handler)
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(context)
}
