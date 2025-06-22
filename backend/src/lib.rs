#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![allow(missing_docs)]

// Re-export modules needed for tests
pub mod app;
pub mod auth;
pub mod db;
pub mod routes;