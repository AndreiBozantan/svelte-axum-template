#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![allow(missing_docs)]

pub mod core {
    mod config;
    mod context;
    mod db;

    pub use config::*;
    pub use context::*;
    pub use db::*;
}

pub mod auth {
    mod jwt;
    mod oauth;
    mod password;

    pub use jwt::*;
    pub use oauth::*;
    pub use password::*;
}

pub mod store {
    mod users;
    mod tenants;
    mod refresh_tokens;

    pub use users::*;
    pub use tenants::*;
    pub use refresh_tokens::*;
}

pub mod routes {
    pub mod api;
    pub mod auth;
    pub mod assets;
    pub mod health;
}

pub mod app {
    mod cli;
    mod migrations;
    mod router;

    pub use cli::*;
    pub use migrations::*;
    pub use router::*;
}
