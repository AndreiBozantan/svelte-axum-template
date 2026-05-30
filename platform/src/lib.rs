#![deny(clippy::all)]
#![warn(clippy::nursery)]
#![warn(clippy::pedantic)]
#![warn(clippy::todo)]
// #![warn(clippy::cargo)]
#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]

// platform implementation
pub mod assets;
pub mod auth;
pub mod common;
pub mod config;
pub mod constants;
pub mod db;
pub mod jwt;
pub mod logger;
pub mod migrations;
pub mod password;
pub mod sso;
pub mod tokens;
pub mod utils;

// identity domain implementation
pub mod handlers;
pub mod models;
pub mod routes;
pub mod queries;
