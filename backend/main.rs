#![deny(clippy::all)]
#![warn(clippy::nursery)]
#![warn(clippy::pedantic)]
#![warn(clippy::todo)]
#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::enum_variant_names)]

#[tokio::main]
async fn main() {
    server::run().await;
}

pub mod cli;
pub mod router;
pub mod server;

pub mod app {
    pub mod sample {
        #[path = "sample_api.rs"]
        pub mod api;
    }
}

mod platform {
    pub mod identity {
        pub mod auth {
            #[path = "auth_api.rs"]
            pub mod api;

            #[path = "auth_service.rs"]
            mod service;

            #[cfg(test)]
            #[path = "auth_tests.rs"]
            mod tests;

            pub use service::*;
        }

        pub mod oauth {
            #[path = "oauth_api.rs"]
            pub mod api;

            #[path = "oauth_service.rs"]
            mod service;

            pub use service::*;
        }

        pub mod users {
            #[path = "users_api.rs"]
            pub mod api;

            #[path = "users_db.rs"]
            pub mod db;

            #[path = "users_service.rs"]
            mod service;

            pub use service::*;
        }

        pub mod tokens {
            #[path = "tokens_db.rs"]
            pub mod db;

            #[path = "tokens_service.rs"]
            mod service;

            pub use service::*;
        }
    }

    pub mod shared {
        pub mod api;
        pub mod assets;
        pub mod common;
        pub mod config;
        pub mod constants;
        pub mod cookies;
        pub mod crypto;
        pub mod db;
        pub mod jwt;
        pub mod migrations;
    }

    pub use shared::*;
}

#[cfg(test)]
mod test {
    pub mod test_server;

    mod app {
        mod sample {
            mod sample_tests;
        }
    }

    mod platform {
        mod identity {
            mod auth_tests;
            mod users_tests;
            mod validate_redirect_path_tests;
        }

        mod shared {
            mod auth_tests;
            mod crypto_tests;
            mod jwt_tests;
        }
    }
}
