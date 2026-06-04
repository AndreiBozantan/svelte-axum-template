#![deny(clippy::all)]
#![warn(clippy::nursery)]
#![warn(clippy::pedantic)]
#![warn(clippy::todo)]
// #![warn(clippy::cargo)]
#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]

pub mod shared {
    pub mod cli;
    pub mod common;
    pub mod config;
    pub mod constants;
    pub mod logger;
    pub mod migrations;
}

pub use shared::*;

pub mod crypto
{
    pub mod auth;
    pub mod jwt;
    pub mod password;
    pub mod sso;
    pub mod tokens;
}

// identity bounded context 
pub mod identity {
    pub mod auth {
        pub mod api;
        pub mod repo;
        pub mod service;
    }
}
