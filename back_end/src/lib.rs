#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![allow(missing_docs)]

// Re-export modules needed for tests
pub mod routes;
pub mod jwt;
pub mod db;
pub mod middlewares;
pub mod appconfig;
pub mod appcontext;
pub mod store;