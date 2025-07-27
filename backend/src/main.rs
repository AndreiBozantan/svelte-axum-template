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

    pub use context::*;
}

pub mod auth {
    mod jwt;
    mod password;

    pub use jwt::*;
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

pub mod services {
    pub mod sso;
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
