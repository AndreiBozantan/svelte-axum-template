#![deny(clippy::all)]
#![warn(clippy::nursery)]
#![warn(clippy::pedantic)]
#![warn(clippy::todo)]
// #![warn(clippy::cargo)]
#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]

#[tokio::main]
async fn main() {
    platform::server::run().await;
}

pub mod platform {
    pub mod assets;
    pub mod cli;
    pub mod common;
    pub mod config;
    pub mod constants;
    pub mod db;
    pub mod jwt;
    pub mod logger;
    pub mod migrations;
    pub mod password;
    pub mod router;
    pub mod server;
    pub mod sso;
    pub mod tokens;
    pub mod utils;
}

pub mod app {
    pub mod identity {
        pub mod identity_api;
        pub mod identity_models;
        pub mod identity_store;
    }
    pub mod system {
        pub mod system_api;
    }
}



#[cfg(test)]
mod tests {
    mod auth_tests;
    mod jwt_tests;
    mod password_tests;
}
