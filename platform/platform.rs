#![deny(clippy::all)]
#![warn(clippy::nursery)]
#![warn(clippy::pedantic)]
#![warn(clippy::todo)]
// #![warn(clippy::cargo)]
#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

pub(crate) mod internal {
    pub mod logger;
    pub mod tokens;
}

pub mod shared {
    pub mod auth;
    pub mod cli;
    pub mod common;
    pub mod config;
    pub mod constants;
    pub mod jwt;
    pub mod migrations;

    #[cfg(test)]
    mod tests;
}

pub use shared::*;

pub mod identity {
    pub(crate) mod auth {
        pub mod api;
        pub mod repo;
        pub mod service;
        pub mod util;
    }

    pub(crate) mod oauth {
        pub mod api;
        pub mod service;
    }

    pub(crate) mod users {
        pub mod api;
        pub mod repo;
        pub mod service;
    }

    #[cfg(test)]
    mod tests;

    pub fn router(ctx: crate::common::ArcContext) -> axum::Router<crate::common::ArcContext> {
        axum::Router::new()
            .merge(auth::api::router())
            .merge(oauth::api::router())
            .merge(users::api::router(ctx))
    }
}
