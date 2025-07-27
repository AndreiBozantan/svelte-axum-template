#![deny(clippy::all)]
#![warn(clippy::nursery)]
#![warn(clippy::pedantic)]
#![warn(clippy::todo)]
// #![warn(clippy::cargo)]

#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]

#[tokio::main]
async fn main() {
    app::run().await;
}

#[cfg(test)]
mod tests {
    mod auth_tests;
}

pub mod core {
    mod config;
    mod context;

    pub use config::*;
    pub use context::*;
}

pub mod auth {
    mod jwt;
    mod oauth;
    mod password;

    pub use jwt::*;
    pub use oauth::*;
    pub use password::*;
}

pub mod db {
    mod refresh_tokens;
    mod tenants;
    mod users;

    pub use refresh_tokens::*;
    pub use tenants::*;
    pub use users::*;
}

pub mod routes {
    pub mod api;
    pub mod assets;
    pub mod auth;
    pub mod health;
}

pub mod app {
    mod server;
    mod cli;
    mod migrations;
    mod router;

    pub use server::*;
    pub use cli::*;
    pub use migrations::*;
    pub use router::*;
}