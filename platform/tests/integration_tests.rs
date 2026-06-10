use axum::http::StatusCode;
use axum_test::TestServer;
use serde_json::Value;
use serde_json::json;

use platform::common;


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
    let ctx = common::Context::create_test_context().await.map_err(|e| anyhow::anyhow!(e))?;

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