#![deny(clippy::all)]
#![warn(clippy::nursery)]
#![warn(clippy::pedantic)]
#![warn(clippy::todo)]
// #![warn(clippy::cargo)]
#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]

#[path = "auth/auth.rs"]
pub mod auth;

#[path = "auth/jwt.rs"]
pub mod jwt;

#[path = "auth/password.rs"]
pub mod password;

#[path = "auth/sso.rs"]
pub mod sso;

#[path = "auth/tokens.rs"]
pub mod tokens;

#[path = "misc/assets.rs"]
pub mod assets;

#[path = "misc/common.rs"]
pub mod common;

#[path = "misc/config.rs"]
pub mod config;

#[path = "misc/constants.rs"]
pub mod constants;

#[path = "misc/db.rs"]
pub mod db;

#[path = "misc/logger.rs"]
pub mod logger;

#[path = "misc/migrations.rs"]
pub mod migrations;

#[path = "misc/utils.rs"]
pub mod utils;

// identity domain implementation
pub mod identity {
    pub mod handlers;

    pub mod models;

    pub mod routes;

    pub mod queries;

    #[cfg(test)]
    pub mod tests;
}
