#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![allow(missing_docs)]

pub mod core {
    mod config;
    mod context;
    mod dberror;

    pub use config::*;
    pub use context::*;
    pub use dberror::*;
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
    mod app;
    mod cli;
    mod migrations;
    mod router;

    pub use app::*;
    pub use cli::*;
    pub use migrations::*;
    pub use router::*;
}
