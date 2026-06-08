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
}

pub mod shared {
    pub mod api;
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
        mod service;

        pub use service::*;

        #[cfg(test)]
        mod tests;
    }

    pub(crate) mod oauth {
        pub mod api;
        mod service;

        pub use service::*;
    }

    pub(crate) mod users {
        pub mod api;
        pub mod db;
        mod service;

        pub use service::*;
    }

    pub(crate) mod tokens {
        pub mod db;
        mod service;
        pub mod utils;

        pub use service::*;
    }

    #[cfg(test)]
    mod tests;

    pub fn router(ctx: crate::common::ArcContext) -> axum::Router<crate::common::ArcContext> {
        let auth_service = auth::Service::new(users::db::Repository, tokens::db::Repository);

        axum::Router::new()
            .merge(auth::api::router(ctx.clone(), auth_service.clone()))
            .merge(oauth::api::router(ctx.clone(), auth_service))
            .merge(users::api::router(ctx, users::db::Repository))
    }
}
