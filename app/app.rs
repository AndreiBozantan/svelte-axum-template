#![deny(clippy::all)]
#![warn(clippy::nursery)]
#![warn(clippy::pedantic)]
#![warn(clippy::todo)]
#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]

use std::error::Error;
use std::net::SocketAddr;
use std::str::FromStr;

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http;
use axum::http::Uri;
use axum::http::header;
use axum::response::IntoResponse;
use axum::response::Response;
use chrono::TimeZone;
use chrono::Utc;
use rust_embed::RustEmbed;
use serde::Serialize;
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::sqlite::SqlitePoolOptions;
use thiserror::Error;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use platform::api;
use platform::common;
use platform::common::ArcContext;
use platform::config;
use platform::db;
use platform::jwt;
use platform::migrations;

#[tokio::main]
async fn main() {
    #[cfg(debug_assertions)]
    {
        dotenvy::dotenv().ok();
    }
    if let Err(error) = run_app().await {
        eprintln!("❌ {error}\n");
        let mut source = error.source();
        while let Some(err) = source {
            eprintln!("Caused by: {err}");
            source = err.source();
        }
        let backtrace = std::backtrace::Backtrace::capture();
        eprintln!("{backtrace}");
        std::process::exit(1);
    }
}

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Configuration error: {0}")]
    ConfigLoadingFailed(#[from] ::config::ConfigError),

    #[error("Database error: {0}")]
    DatabaseOperationFailed(#[from] sqlx::Error),

    #[error("JWT error: {0}")]
    JwtOperationFailed(#[from] jwt::Error),

    #[error("Migration error: {0}")]
    MigrationFailed(#[from] migrations::MigrationError),

    #[error("CLI error: {0}")]
    CliOperationFailed(#[from] platform::cli::Error),

    #[error("Network address parsing error: {0}")]
    AddressParsingFailed(#[from] std::net::AddrParseError),

    #[error("Server error: {0}")]
    ServerStartingFailed(#[from] std::io::Error),

    #[error("Server error: {0}")]
    HttpClientCreationFailed(#[from] reqwest::Error),
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
    let jwt = jwt::Context::new(&settings.jwt, &jwt_secret)?;
    let ctx = common::Context::new(db, jwt, settings, http_client).into();

    if !platform::cli::run_cli(&ctx).await? {
        migrations::run_migrations(&ctx).await?;
        start_server(ctx).await?;
    }
    Ok(())
}

async fn start_server(ctx: common::ArcContext) -> Result<(), AppError> {
    let addr = ctx.settings.get_server_address().parse::<SocketAddr>()?;
    let router = create_router(ctx.clone()).into_make_service_with_connect_info::<SocketAddr>();
    let listener = tokio::net::TcpListener::bind(addr).await?;
    platform::auth::check_oauth_config(&ctx.settings.oauth);
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

async fn shutdown_signal() {
    match tokio::signal::ctrl_c().await {
        Ok(()) => tracing::info!("Shutdown signal received, shutting down gracefully"),
        Err(error) => tracing::error!("Failed to listen for shutdown signal: {}", error),
    }
}

#[derive(RustEmbed)]
#[folder = "../frontend/dist"]
struct Assets;

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

fn create_router(context: ArcContext) -> Router {
    let public = Router::new()
        .route("/health", axum::routing::get(health_check))
        .with_state(context.clone());

    let api = Router::new()
        .merge(platform::identity::router(context.clone()))
        .merge(public)
        .fallback(|| async { api::Error::not_found() });

    Router::new()
        .nest("/api", api)
        .fallback(static_handler)
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(context)
}

async fn create_db_context(db_config: &config::DatabaseSettings) -> Result<db::Context, sqlx::Error> {
    let options = SqliteConnectOptions::from_str(&db_config.url)?
        .create_if_missing(true)
        .foreign_keys(true)
        .busy_timeout(std::time::Duration::from_secs(30));
    let pool = SqlitePoolOptions::new()
        .max_connections(db_config.max_connections)
        .connect_with(options)
        .await?;
    sqlx::query("PRAGMA journal_mode = WAL").execute(&pool).await?;
    if db_config.store_temp_tables_in_memory {
        sqlx::query("PRAGMA temp_store = MEMORY").execute(&pool).await?;
    }
    Ok(pool)
}

#[derive(Debug, Error)]
enum AssetError {
    #[error("Failed to build response: {0}")]
    ResponseBuildError(#[from] http::Error),

    #[error("Asset not found: {0}")]
    NotFound(String),
}

impl IntoResponse for AssetError {
    fn into_response(self) -> Response {
        tracing::error!("{self}");
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
async fn static_handler(uri: Uri) -> Result<impl IntoResponse, AssetError> {
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

type Builder = http::response::Builder;

fn create_index_response_builder(asset: &rust_embed::EmbeddedFile) -> Builder {
    let etag = hex::encode(asset.metadata.sha256_hash());
    Response::builder()
        .header(header::CONTENT_TYPE, "text/html")
        .header(header::CACHE_CONTROL, "no-cache")
        .header(header::ETAG, etag)
}

fn create_asset_response_builder(asset: &rust_embed::EmbeddedFile, path: &str) -> Builder {
    let mime_type = mime_guess::from_path(path).first_or_octet_stream();
    let etag = hex::encode(asset.metadata.sha256_hash());
    let builder = Response::builder()
        .header(header::CONTENT_TYPE, mime_type.as_ref())
        .header(header::CACHE_CONTROL, "public, max-age=31536000, immutable")
        .header(header::ETAG, etag);
    match asset_last_modified(asset) {
        Some(last_modified) => builder.header(header::LAST_MODIFIED, last_modified),
        None => builder,
    }
}

#[allow(clippy::cast_possible_wrap)]
fn asset_last_modified(asset: &rust_embed::EmbeddedFile) -> Option<String> {
    asset
        .metadata
        .last_modified()
        .and_then(|ts| Utc.timestamp_opt(ts as i64, 0).single())
        .map(|dt| dt.to_rfc2822())
}
