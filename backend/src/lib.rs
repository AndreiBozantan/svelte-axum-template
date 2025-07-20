#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![allow(missing_docs)]

pub mod core {
    mod config;

    pub use config::*;
}

pub mod store {
    mod users;
    mod tenants;
    mod refresh_tokens;

    pub use users::*;
    pub use tenants::*;
    pub use refresh_tokens::*;
}

pub mod auth {
    mod password;
    mod jwt;
    mod oauth;

    pub use password::*;
    pub use jwt::*;
    pub use oauth::*;
}

pub mod routes {
    pub mod api;
    pub mod auth;
    pub mod assets;
    pub mod health;
}

pub mod app {
    mod db;
    mod context;
    mod router;

    pub mod cli;

    pub use db::*;
    pub use context::*;
    pub use router::*;
}

