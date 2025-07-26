use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::error::Error;
use std::net::SocketAddr;
use std::str::FromStr;
use thiserror::Error;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::app;
use crate::core;

/// Application-level error type
#[derive(Debug, Error)]
pub enum AppError {
    #[error("Configuration error: {0}")]
    ConfigLoadingFailed(#[from] config::ConfigError),

    #[error("Database error: {0}")]
    DatabaseOperationFailed(#[from] core::DbError),

    #[error("Migration error: {0}")]
    MigrationFailed(#[from] app::MigrationError),

    #[error("CLI error: {0}")]
    CliOperationFailed(#[from] app::CliError),

    #[error("Network address parsing error: {0}")]
    AddressParsingFailed(#[from] std::net::AddrParseError),

    #[error("Server error: {0}")]
    ServerStartingFailed(#[from] std::io::Error),

    #[error("Server error: {0}")]
    HttpClientError(#[from] reqwest::Error),
}

pub async fn create_db_context(db_config: &core::DatabaseConfig) -> Result<core::DbContext, core::DbError> {
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
    // TODO: use dot-env to load environment variables
    // dotenvy::dotenv().ok();

    let config = core::ConfigWithMetadata::new()?;
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(&config.data.server.log_directives))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // initialize database and run CLI
    let db = create_db_context(&config.data.database).await?;
    let context = core::Context::new(db, config.data)?;
    app::run_cli(&context).await?;

    let address = config.metadata.server_address.parse::<SocketAddr>()?;
    let listener = tokio::net::TcpListener::bind(address).await?;
    let router = app::create_router(context);
    tracing::info!("🚀 starting server");
    tracing::info!("   app_env: {}", config.metadata.app_run_env);
    tracing::info!("   cfg_dir: {}", config.metadata.config_dir);
    tracing::info!("   logging: {}", config.metadata.log_directives);
    tracing::info!("   address: http://{}", config.metadata.server_address);

    tracing::debug!("test debug log");

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

/// Tokio signal handler that will wait for a user to press CTRL+C.
/// We use this in our `Server` method `with_graceful_shutdown`.
async fn shutdown_signal() {
    match tokio::signal::ctrl_c().await {
        Ok(()) => tracing::info!("Shutdown signal received, shutting down gracefully"),
        Err(e) => tracing::error!("Failed to listen for shutdown signal: {}", e),
    }
}
