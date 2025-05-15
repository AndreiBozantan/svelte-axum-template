#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![allow(missing_docs)]

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use tower_sessions::{MemoryStore, SessionManagerLayer};
use tracing::log::warn;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use thiserror::Error;

pub mod assets;
pub mod cli;
pub mod db;
pub mod middlewares;
pub mod routes;
pub mod auth_utils;
mod appconfig;
mod services;
mod store;

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
    // load config
    let config = appconfig::AppConfig::new()?;

    // start tracing - level set by either RUST_LOG env variable or defaults to debug
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(&config.server.log_directives))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Initialize database connection pool
    let db_pool = db::init_pool(&config.database).await?;

    // Run migration CLI if requested
    cli::run_migration_cli(&db_pool).await?;

    let addr: SocketAddr = format!("{h}:{p}", h = config.server.host, p = config.server.port)
        .parse()?;    // create store for backend, including the database pool
    let shared_state = Arc::new(store::Store::new_with_jwt(
        &config.server.api_token, 
        db_pool,
        &config.jwt
    ));

    // setup up sessions and store to keep track of session information
    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store).with_name(config.server.session_cookie_name);

    // combine the front and backend into server
    let app = Router::new()
        .merge(services::front_public_route())
        .merge(services::backend(session_layer, shared_state));

    tracing::info!("🚀 listening on http://{addr}");

    let listener = tokio::net::TcpListener::bind(addr).await?;

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

#[tokio::main]
async fn main() {
    if let Err(e) = run_app().await {
        tracing::error!("Application error: {}", e);
        std::process::exit(1);
    }
}

/// Tokio signal handler that will wait for a user to press CTRL+C.
/// We use this in our `Server` method `with_graceful_shutdown`.
async fn shutdown_signal() {
    match tokio::signal::ctrl_c().await {
        Ok(()) => tracing::info!("Shutdown signal received, shutting down gracefully"),
        Err(e) => tracing::error!("Failed to listen for shutdown signal: {}", e),
    }
}