#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![allow(missing_docs)]

use std::net::SocketAddr;

use axum::Router;
use tracing::log::warn;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use thiserror::Error;

pub mod assets;
pub mod cli;
pub mod db;
pub mod jwt;
pub mod middlewares;
pub mod password;
pub mod routes;
mod appconfig;
mod services;
mod state;
mod store;

use crate::state::AppState;

/// Application-level error type
#[derive(Debug, Error)]
pub enum AppError {
    #[error("Configuration error: {0}")]
    Config(#[from] config::ConfigError),

    #[error("Database error: {0}")]
    Database(#[from] db::DbError),

    #[error("Migration error: {0}")]
    Migration(#[from] db::migrations::MigrationError),

    #[error("CLI error: {0}")]
    CliError(#[from] cli::CliError),

    #[error("Network address parsing error: {0}")]
    AddrParse(#[from] std::net::AddrParseError),

    #[error("Server error: {0}")]
    Server(#[from] std::io::Error),
}

/// Server that is split into a Frontend to serve static files (Svelte) and Backend
/// Backend is further split into a non authorized area and a secure area
/// The Back end is using 2 middleware: sessions (managing session data) and user_secure (checking for authorization)
async fn run_app() -> Result<(), AppError> {
    let config = appconfig::AppConfig::new()?;

    // start tracing - level set by either RUST_LOG env variable or defaults to debug
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(&config.server.log_directives))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // initialize database
    let db_pool = db::init_pool(&config.database).await?;
    cli::run_migration_cli(&db_pool).await?;

    // setup server
    let addr: SocketAddr = format!("{h}:{p}", h = config.server.host, p = config.server.port).parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let app_state = AppState::new(db_pool, config);
    let router = Router::new()
        .merge(services::front_public_route())
        .merge(services::backend(&app_state));

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