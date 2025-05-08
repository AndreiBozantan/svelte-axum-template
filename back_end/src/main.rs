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

pub mod assets;
pub mod cli;
pub mod db;
pub mod middlewares;
pub mod routes;
mod appconfig;
mod services;
mod store;

/// Server that is split into a Frontend to serve static files (Svelte) and Backend
/// Backend is further split into a non authorized area and a secure area
/// The Back end is using 2 middleware: sessions (managing session data) and user_secure (checking for authorization)
#[tokio::main]
async fn main() {
    // load config
    let config = appconfig::AppConfig::new().unwrap_or_else(|e| {
        warn!("Failed to load config: {:?}", e);
        std::process::exit(1);
    });

    // start tracing - level set by either RUST_LOG env variable or defaults to debug
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(config.server.log_directives))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Initialize database connection pool
    let db_pool = match db::init_pool(&config.database).await {
        Ok(pool) => pool,
        Err(e) => {
            tracing::error!("Failed to initialize database: {:?}", e);
            std::process::exit(2);
        }
    };

    // Run migration CLI if requested
    if let Err(e) = cli::run_migration_cli(&db_pool).await {
        tracing::error!("Migration CLI error: {:?}", e);
        std::process::exit(3);
    }

    let addr: SocketAddr = format!("{h}:{p}", h = config.server.host, p = config.server.port)
        .parse()
        .expect("Can not parse address and port");

    // create store for backend, including the database pool
    let shared_state = Arc::new(store::Store::new(&config.server.api_token, db_pool));

    // setup up sessions and store to keep track of session information
    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store).with_name(config.server.session_cookie_name);

    // combine the front and backend into server
    let app = Router::new()
        .merge(services::front_public_route())
        .merge(services::backend(session_layer, shared_state));

    // println!("🚀 Server starting on http://{}", addr);
    tracing::info!("🚀 listening on http://{addr}");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
}

/// Tokio signal handler that will wait for a user to press CTRL+C.
/// We use this in our `Server` method `with_graceful_shutdown`.
async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Expect shutdown signal handler");
    println!("signal shutdown");
}