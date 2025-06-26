#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![allow(missing_docs)]

// Re-export modules needed for tests
pub mod routes;

pub mod db {
    pub mod store;
    pub mod schema;
    pub mod migrations;

    pub use store::{Store, StoreError};

    pub use migrations::MigrationError;
}

// Auth module and re-exports
pub mod auth {
    pub mod jwt;
    pub mod oauth;
    pub mod password;

    pub use password::{hash_password, verify_password};
}

pub mod app {
    mod config;
    mod context;

    pub mod cli;

    pub use context::Context;

    pub use config::Config;
    pub use config::DatabaseConfig;
    pub use config::ServerConfig;
    pub use config::JwtConfig;
}