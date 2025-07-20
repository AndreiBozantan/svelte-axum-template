#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![allow(missing_docs)]

pub mod app {
    mod config;
    mod context;
    mod router;
    mod db;

    pub mod cli;

    pub use db::*;
    pub use config::*;
    pub use context::*;
    pub use router::*;
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

pub mod store {
    mod refresh_tokens;
    mod tenants;
    mod users;

    pub use users::*;
    pub use tenants::*;
    pub use refresh_tokens::*;
}
