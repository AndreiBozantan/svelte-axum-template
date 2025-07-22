#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![allow(missing_docs)]

use svelte_axum_template::app;

#[tokio::main]
async fn main() {
    if let Err(e) = app::run_app().await {
        tracing::error!("Application error: {}", e);
        std::process::exit(1);
    }
}