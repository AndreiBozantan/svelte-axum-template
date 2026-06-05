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
        pub mod db;
        pub mod domain;
        pub mod util;
    }

    pub(crate) mod oauth {
        pub mod api;
        pub mod domain;
    }

    pub(crate) mod users {
        pub mod api;
        pub mod db;
        pub mod domain;
    }

    #[cfg(test)]
    mod tests;

    pub fn router(ctx: crate::common::ArcContext) -> axum::Router<crate::common::ArcContext> {
        let user_service = users::domain::Service::new(users::db::Repository);
        let auth_service = auth::domain::Service::new(user_service.clone(), auth::db::Repository);

        axum::Router::new()
            .merge(auth::api::router(ctx.clone(), auth_service.clone()))
            .merge(oauth::api::router(ctx.clone(), auth_service, user_service.clone()))
            .merge(users::api::router(ctx, user_service))
    }
}
