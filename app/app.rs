#![deny(clippy::all)]
#![warn(clippy::nursery)]
#![warn(clippy::pedantic)]
#![warn(clippy::todo)]
// #![warn(clippy::cargo)]
#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]

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

#[tokio::main]
async fn main() {
    server::run().await;
}

#[derive(RustEmbed)]
#[folder = "../frontend/dist"]
pub struct Assets;

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

    tracing::info!("starting server... 🚀 ");
    tracing::info!("logging: {}", settings.server.log_directives);
    tracing::info!("app_env: {}", settings.server.env);
    tracing::info!("sql_url: {}", settings.database.url);
    tracing::info!("cfg_dir: {}", settings.get_config_dir_str()?);
    tracing::info!("address: http://{}", settings.get_server_address());

    let http_client = create_http_client()?;
    let db = create_db_context(&settings.database).await?;
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
    sso::check_oauth_config(&ctx.settings.oauth);
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
    platform::identity::db::get_tenant_by_id(&context.db, 0)
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

fn create_router(context: ArcContext) -> Router {
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

async fn create_db_context(db_config: &config::DatabaseSettings) -> Result<db::SqlContext, db::SqlError> {
    let options = SqliteConnectOptions::from_str(&db_config.url)?
        .create_if_missing(true)
        .foreign_keys(true)
        // Increase SQLite busy timeout to handle concurrent connections better
        .busy_timeout(std::time::Duration::from_secs(30));
    let pool = SqlitePoolOptions::new()
        .max_connections(db_config.max_connections)
        .connect_with(options)
        .await?;
    // enable WAL mode for better concurrency
    sqlx::query("PRAGMA journal_mode = WAL").execute(&pool).await?;
    if db_config.store_temp_tables_in_memory {
        // store temporary tables in memory for better performance
        sqlx::query("PRAGMA temp_store = MEMORY").execute(&pool).await?;
    }
    Ok(pool)
}

#[derive(Debug, Error)]
pub enum AssetError {
    #[error("Failed to build response: {0}")]
    ResponseBuildError(#[from] http::Error),

    #[error("Asset not found: {0}")]
    NotFound(String),
}

impl IntoResponse for AssetError {
    fn into_response(self) -> axum::response::Response {
        tracing::error!("{}", &self);

        let status = match self {
            Self::ResponseBuildError(_) => http::StatusCode::INTERNAL_SERVER_ERROR,
            Self::NotFound(_) => http::StatusCode::NOT_FOUND,
        };

        let body = match self {
            Self::ResponseBuildError(_) => "Internal server error".to_string(),
            Self::NotFound(path) => format!("Asset not found: {path}"),
        };

        (status, body).into_response()
    }
}

#[allow(clippy::unused_async)]
pub async fn static_handler(uri: Uri) -> Result<impl IntoResponse, AssetError> {
    let path_str = uri.path().trim_start_matches('/');
    let path_str = if path_str.is_empty() { "index.html" } else { path_str };
    let asset = Assets::get(path_str);
    let path_str = if asset.is_none() { "index.html" } else { path_str };
    let asset = asset
        .or_else(|| Assets::get(path_str))
        .ok_or_else(|| AssetError::NotFound(path_str.to_string()))?;
    let builder = match path_str {
        "index.html" => create_index_response_builder(&asset),
        _ => create_asset_response_builder(&asset, path_str),
    };
    Ok(builder.body(Body::from(asset.data.to_vec()))?.into_response())
}

fn create_index_response_builder(asset: &EmbeddedFile) -> Builder {
    let etag = hex::encode(asset.metadata.sha256_hash());
    Response::builder()
        .header(header::CONTENT_TYPE, "text/html")
        // no-cache means "must revalidate with server", but allows 304 Not Modified if ETag matches
        .header(header::CACHE_CONTROL, "no-cache")
        .header(header::ETAG, etag)
}

fn create_asset_response_builder(asset: &EmbeddedFile, path: &str) -> Builder {
    let mime_type = mime_guess::from_path(path).first_or_octet_stream();
    let etag = hex::encode(asset.metadata.sha256_hash());
    let builder = Response::builder()
        .header(header::CONTENT_TYPE, mime_type.as_ref())
        .header(header::CACHE_CONTROL, "public, max-age=31536000, immutable")
        .header(header::ETAG, etag);
    match get_asset_last_modified_date(asset) {
        Some(last_modified) => builder.header(header::LAST_MODIFIED, last_modified),
        None => builder,
    }
}

#[allow(clippy::cast_possible_wrap)] // the timestamp will be in the range of i64 for quite some time
fn get_asset_last_modified_date(asset: &EmbeddedFile) -> Option<String> {
    asset
        .metadata
        .last_modified()
        .and_then(|ts| Utc.timestamp_opt(ts as i64, 0).single())
        .map(|dt| dt.to_rfc2822())
}
