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

pub mod cfg {
    mod app_settings;
    mod database_settings;
    mod jwt_settings;
    mod oauth_settings;
    mod server_settings;

    pub use app_settings::*;
    pub use database_settings::*;
    pub use jwt_settings::*;
    pub use oauth_settings::*;
    pub use server_settings::*;
}

pub mod core {
    mod context;
    mod dbtypes;

    pub use context::*;
    pub use dbtypes::*;
}

pub mod auth {
    mod error;
    mod jwt;
    mod logger;
    mod password;
    mod sso;
    mod tokens;

    pub use error::*;
    pub use jwt::*;
    pub use logger::*;
    pub use password::*;
    pub use sso::*;
    pub use tokens::*;
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
    pub mod user_info;
}

pub mod middleware {
    mod rate_limit;

    pub use rate_limit::*;
}

pub mod app {
    mod cli;
    mod migrations;
    mod router;
    mod server;

    pub use cli::*;
    pub use migrations::*;
    pub use router::*;
    pub use server::*;
}

#[cfg(test)]
mod tests {
    mod auth_tests;
    mod jwt_tests;
    mod password_tests;
}
