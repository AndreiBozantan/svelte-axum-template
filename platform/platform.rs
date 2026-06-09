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
    pub mod db;
    pub mod config;
    pub mod constants;
    pub mod jwt;
    pub mod migrations;
}

pub use shared::*;

pub mod identity {
    pub(crate) mod auth {
        #[path ="auth_api.rs"]
        pub mod api;

        #[path ="auth_service.rs"]
        mod service;

        pub use service::*;
    }

    pub(crate) mod oauth {
        #[path ="oauth_api.rs"]
        pub mod api;

        #[path ="oauth_service.rs"]
        mod service;

        pub use service::*;
    }

    pub(crate) mod users {
        #[path ="users_api.rs"]
        pub mod api;

        #[path ="users_db.rs"]
        pub mod db;

        #[path ="users_service.rs"]
        mod service;

        pub use service::*;
    }

    pub(crate) mod tokens {
        #[path ="tokens_db.rs"]
        pub mod db;

        #[path ="tokens_service.rs"]
        mod service;
        
        #[path ="tokens_utils.rs"]
        pub mod utils;

        pub use service::*;
        
        #[cfg(test)]
        #[path ="tokens_tests.rs"]
        mod tests;
    }

    pub fn router(ctx: crate::common::ArcContext) -> axum::Router<crate::common::ArcContext> {
        let auth_service = auth::Service::new(users::db::Repository, tokens::db::Repository);

        axum::Router::new()
            .merge(auth::api::router(ctx.clone(), auth_service.clone()))
            .merge(oauth::api::router(ctx.clone(), auth_service))
            .merge(users::api::router(ctx, users::db::Repository))
    }
}
