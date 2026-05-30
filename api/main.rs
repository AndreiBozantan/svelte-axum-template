#![deny(clippy::all)]
#![warn(clippy::nursery)]
#![warn(clippy::pedantic)]
#![warn(clippy::todo)]
// #![warn(clippy::cargo)]
#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]

#[tokio::main]
async fn main() {
    server::run().await;
}

pub mod cli;
pub mod server;
