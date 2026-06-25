use axum::http::StatusCode;
use axum_test::TestServer;
use serde_json::Value;
use serde_json::json;

use crate::router;

use crate::platform::common;

pub type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub const TEST_USER_EMAIL: &str = "test@example.com";
pub const TEST_PASSWORD: &str = "abcdefghijklmnopqrstuvwxyz";

pub async fn login_testuser_and_get_tokens(server: &TestServer) -> TestResult<(Value, String, String)> {
    let response = server
        .post("/api/auth/login")
        .json(&json!({
            "email": TEST_USER_EMAIL,
            "password": TEST_PASSWORD,
        }))
        .await;
    response.assert_status(StatusCode::OK);
    let body: Value = response.json();
    let refresh_token = response.cookie("__Secure-refresh_token").value().to_string();
    let access_token = response.cookie("__Host-access_token").value().to_string();
    assert!(!access_token.is_empty());
    assert!(!refresh_token.is_empty());
    Ok((body, access_token, refresh_token))
}

pub async fn create_test_server() -> TestResult<TestServer> {
    let ctx = common::Context::create_test_context().await?;
    let router = router::create(ctx.clone());
    let server = TestServer::new(router.into_make_service_with_connect_info::<std::net::SocketAddr>());

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

pub async fn create_test_context_and_server() -> TestResult<(common::ArcContext, TestServer)> {
    let ctx = common::Context::create_test_context().await?;
    let router = router::create(ctx.clone());
    let server = TestServer::new(router.into_make_service_with_connect_info::<std::net::SocketAddr>());
    Ok((ctx, server))
}

#[tokio::test]
async fn test_static_file_caching() -> TestResult {
    let server = create_test_server().await?;

    // Request index.html first time (should be 200 OK)
    let response = server.get("/").await;
    response.assert_status(StatusCode::OK);

    let etag = response
        .headers()
        .get(axum::http::header::ETAG)
        .ok_or("ETag header is missing")?
        .to_str()?
        .to_string();

    assert!(!etag.is_empty(), "ETag should not be empty");

    // Request index.html second time with If-None-Match (should be 304 Not Modified)
    let response_cached = server
        .get("/")
        .add_header(axum::http::header::IF_NONE_MATCH, &etag)
        .await;

    response_cached.assert_status(StatusCode::NOT_MODIFIED);
    assert!(response_cached.text().is_empty(), "304 response body should be empty");
    Ok(())
}

#[tokio::test]
async fn test_static_file_routing() -> TestResult {
    let server = create_test_server().await?;

    // navigation route (no extension) should fall back to serving index.html (200 OK)
    let response_nav = server.get("/some/client/route").await;
    response_nav.assert_status(StatusCode::OK);
    let nav_text = response_nav.text();
    assert!(nav_text.contains("</html>"));

    // request for non-existent file with extension (e.g. .png) should return 404 NOT FOUND
    let response_missing_file = server.get("/assets/non-existent-image.png").await;
    response_missing_file.assert_status(StatusCode::NOT_FOUND);

    // request for non-existent file under /static should return 404 NOT FOUND
    let response_missing_static = server.get("/static/assets/non-existent-image.png").await;
    response_missing_static.assert_status(StatusCode::NOT_FOUND);

    // request for existing file under root should succeed
    let response_static_file = server.get("/favicon.ico").await;
    response_static_file.assert_status(StatusCode::OK);

    // request a dynamically discovered file under /static to verify static serving
    if let Some(static_path) = crate::platform::shared::assets::get_embedded_static_paths().first() {
        let route = format!("/{static_path}");
        let response = server.get(&route).await;
        response.assert_status(StatusCode::OK);
    }

    Ok(())
}

#[tokio::test]
async fn test_panic_handling() -> TestResult {
    let server = create_test_server().await?;

    // normal health check (should be 200 OK)
    let response = server.get("/api/health").await;
    response.assert_status(StatusCode::OK);

    // health check with panic=true (should trigger panic and return 500 JSON error)
    let response_panic = server.get("/api/health?panic=true").await;
    response_panic.assert_status(StatusCode::INTERNAL_SERVER_ERROR);

    let body: Value = response_panic.json();
    assert_eq!(body["code"], "internal_error");
    assert_eq!(body["message"], "An unexpected error occurred.");

    Ok(())
}
