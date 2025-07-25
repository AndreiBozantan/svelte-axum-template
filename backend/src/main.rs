#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![allow(missing_docs)]

#[tokio::main]
async fn main() {
    svelte_axum_template::app::run().await
}