use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::error::Error;
use std::net::SocketAddr;
use std::str::FromStr;
use thiserror::Error;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::app;
use crate::auth;
use crate::cfg;
use crate::core;

/// Application-level error type
#[derive(Debug, Error)]
pub enum AppError {
    #[error("Configuration error: {0}")]
    ConfigLoadingFailed(#[from] config::ConfigError),

    #[error("Database error: {0}")]
    DatabaseOperationFailed(#[from] core::DbError),

    #[error("JWT error: {0}")]
    JwtOperationFailed(#[from] auth::JwtError),

    #[error("Migration error: {0}")]
    MigrationFailed(#[from] app::MigrationError),

    #[error("CLI error: {0}")]
    CliOperationFailed(#[from] app::CliError),

    #[error("Network address parsing error: {0}")]
    AddressParsingFailed(#[from] std::net::AddrParseError),

    #[error("Server error: {0}")]
    ServerStartingFailed(#[from] std::io::Error),

    #[error("Server error: {0}")]
    HttpClientCreationFailed(#[from] reqwest::Error),
}

pub async fn create_db_context(db_config: &cfg::DatabaseSettings) -> Result<core::DbContext, core::DbError> {
    let options = SqliteConnectOptions::from_str(&db_config.url)?
        .create_if_missing(true)
        .foreign_keys(true)
        // Increase SQLite busy timeout to handle concurrent connections better
        .busy_timeout(std::time::Duration::from_secs(30));
    let pool = SqlitePoolOptions::new()
        .max_connections(db_config.max_connections)
        .connect_with(options)
        .await?;
    Ok(pool)
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
    let settings = cfg::AppSettings::new()?;
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(&settings.server.log_directives))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let http_client = create_http_client()?;
    let db = create_db_context(&settings.database).await?;
    let jwt_secret = auth::get_jwt_secret()?;
    let jwt = auth::JwtContext::new(&settings.jwt, &jwt_secret)?;
    let ctx = core::Context::new(db, jwt, http_client, settings);
    app::run_migrations(&ctx.db).await?;
    app::run_cli(&ctx.db).await?;
    start_server(ctx).await?;
    Ok(())
}

async fn start_server(ctx: core::ArcContext) -> Result<(), AppError> {
    let addr = ctx.settings.get_server_address().parse::<SocketAddr>()?;
    let router = app::create_router(ctx.clone());
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("starting server... 🚀 ");
    tracing::info!("app_env: {}", cfg::AppSettings::get_app_run_env());
    tracing::info!("cfg_dir: {}", cfg::AppSettings::get_config_full_path());
    tracing::info!("logging: {}", ctx.settings.server.log_directives);
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
