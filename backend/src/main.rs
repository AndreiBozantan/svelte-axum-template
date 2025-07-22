#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![allow(missing_docs)]

use std::net::SocketAddr;
use thiserror::Error;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use svelte_axum_template::*;

// Note: auth module is defined in lib.rs and used by other modules

/// Application-level error type
#[derive(Debug, Error)]
pub enum AppError {
    #[error("Configuration error: {0}")]
    Config(#[from] config::ConfigError),

    #[error("Database error: {0}")]
    Database(#[from] core::DbError),

    #[error("Migration error: {0}")]
    Migration(#[from] app::DbMigrationError),

    #[error("CLI error: {0}")]
    CliError(#[from] app::CliError),

    #[error("Network address parsing error: {0}")]
    AddrParse(#[from] std::net::AddrParseError),

    #[error("Server error: {0}")]
    Server(#[from] std::io::Error),
}

async fn run_app() -> Result<(), AppError> {
    let config = core::Config::new()?;
    let addr: SocketAddr = format!("{h}:{p}", h = config.server.host, p = config.server.port).parse()?;

    // start tracing - level set by either RUST_LOG env variable or defaults to debug
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(&config.server.log_directives))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // initialize database and run CLI
    let db = core::create_db_pool(&config.database).await?;
    app::run_migration_cli(&db).await?;

    // setup server
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let context = core::Context::new(db, config);
    let router = app::create_router(context.into());

    tracing::info!("🚀 listening on http://{addr}");
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

#[tokio::main]
async fn main() {
    if let Err(e) = run_app().await {
        tracing::error!("Application error: {}", e);
        std::process::exit(1);
    }
}