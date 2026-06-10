use std::str::FromStr;

use axum::http::StatusCode;
use axum_test::TestServer;
use serde_json::Value;
use serde_json::json;
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::sqlite::SqlitePoolOptions;

use platform::common;
use platform::config;
use platform::jwt;
use platform::migrations;


mod identity {
     mod auth_tests;
     mod users_tests;
}

mod shared {
     mod auth_tests;
     mod jwt_tests;
}

pub const TEST_USER_EMAIL: &str = "test@example.com";
pub const TEST_PASSWORD: &str = "abcdefghijklmnopqrstuvwxyz";

pub async fn login_testuser_and_get_tokens(server: &TestServer) -> anyhow::Result<(Value, String, String)> {
    let response = server
        .post("/api/auth/login")
        .json(&json!({
            "email": TEST_USER_EMAIL,
            "password": TEST_PASSWORD,
        }))
        .await;
    response.assert_status(StatusCode::OK);
    let body: Value = response.json();
    let refresh_token = response.cookie("refresh_token").value().to_string();
    let access_token = response.cookie("access_token").value().to_string();
    assert!(!access_token.is_empty());
    assert!(!refresh_token.is_empty());
    Ok((body, access_token, refresh_token))
}

pub async fn create_test_server() -> anyhow::Result<TestServer> {
    let config = config::AppSettings {
        jwt: config::JwtSettings {
            access_token_expiry_minutes: 60,
            refresh_token_expiry_days: 1,
        },
        server: config::ServerSettings {
            env: platform::constants::env::TEST.to_string(),
            ..Default::default()
        },
        database: config::DatabaseSettings {
            url: "sqlite::memory:".to_string(),
            max_connections: 5,
            store_temp_tables_in_memory: true,
        },
        ..Default::default()
    };

    let db_options = SqliteConnectOptions::from_str(&config.database.url)?
        .create_if_missing(true)
        .foreign_keys(true);
    let db = SqlitePoolOptions::new()
        .max_connections(config.database.max_connections)
        .connect_with(db_options)
        .await?;

    let jwt_secret = "test__secret__key__for__jwt__testing";
    let jwt = jwt::Context::new(&config.jwt, jwt_secret)?;
    let http_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let ctx = common::Context::new(db, jwt, config, http_client).into();
    migrations::run_migrations(&ctx).await?;

    let platform_router = platform::identity::router(ctx.clone()).with_state(ctx);
    let api_router = axum::Router::new().nest("/api", platform_router);
    let server = TestServer::new(
        api_router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    );

    // register the test user via the API
    let response = server
        .post("/api/auth/register")
        .json(&json!({
            "email": TEST_USER_EMAIL,
            "password": TEST_PASSWORD,
            "first_name": "Test",
            "last_name": "User"
        }))
        .await;
    response.assert_status(StatusCode::CREATED);

    Ok(server)
}