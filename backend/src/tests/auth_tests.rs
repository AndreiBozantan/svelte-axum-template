use axum::http::StatusCode;
use axum::http::header;
use axum_test::TestServer;
use serde_json::Value;
use serde_json::json;

const TEST_PASSWORD: &str = "abcdefghijklmnopqrstuvwxyz";
const TEST_USERNAME: &str = "test_user";

use crate::app;
use crate::auth;
use crate::core;
use crate::db;

fn default_config() -> core::Config {
    core::Config {
        jwt: core::JwtConfig {
            secret: "test_secret_key_for_testing_only".to_string(),
            access_token_expiry: 3600,
            refresh_token_expiry: 86400,
        },
        ..Default::default()
    }
}

async fn create_test_server(config: core::Config) -> TestServer {
    let mut config = config.clone();

    // use a temporary in-memory SQLite database file and use it for testing
    config.database = core::DatabaseConfig {
        url: "sqlite::memory:".to_string(),
        max_connections: 5,
    };

    let db = app::create_db_context(&config.database).await.unwrap();
    app::run_migrations(&db).await.unwrap();

    // Create test user
    let password_hash = auth::hash_password(TEST_PASSWORD).unwrap();
    let user = db::NewUser {
        username: TEST_USERNAME.to_string(),
        password_hash: Some(password_hash),
        email: Some("test@example.com".to_string()),
        tenant_id: Some(1),
        sso_provider: None,
        sso_id: None,
    };

    let context = core::Context::new(db, config);
    db::create_user(&context.db, user).await.unwrap();

    let router = app::create_router(context.into());
    TestServer::new(router).unwrap()
}

#[tokio::test]
async fn test_login_success() {
    let server = create_test_server(default_config()).await;

    let response = server
        .post("/auth/login")
        .json(&json!({
            "username": TEST_USERNAME,
            "password": TEST_PASSWORD
        }))
        .await;

    response.assert_status(StatusCode::OK);
    let body: Value = response.json();
    assert_eq!(body["result"], "ok");
    assert!(body["tokens"]["access_token"].is_string());
    assert!(body["tokens"]["refresh_token"].is_string());
    assert_eq!(body["user"]["username"], TEST_USERNAME);
}

#[tokio::test]
async fn test_login_invalid_credentials() {
    let server = create_test_server(default_config()).await;

    let response = server
        .post("/auth/login")
        .json(&json!({
            "username": TEST_USERNAME,
            "password": "wrong_password"
        }))
        .await;

    response.assert_status(StatusCode::UNAUTHORIZED);
    let body: Value = response.json();
    assert_eq!(body["result"], "error");
}

#[tokio::test]
async fn test_login_nonexistent_user() {
    let server = create_test_server(default_config()).await;

    let response = server
        .post("/auth/login")
        .json(&json!({
            "username": "nonexistent",
            "password": "password"
        }))
        .await;

    response.assert_status(StatusCode::UNAUTHORIZED);
    let body: Value = response.json();
    assert_eq!(body["result"], "error");
}

#[tokio::test]
async fn test_refresh_token_success() {
    let server = create_test_server(default_config()).await;

    // First login to get tokens
    let login_response = server
        .post("/auth/login")
        .json(&json!({
            "username": TEST_USERNAME,
            "password": TEST_PASSWORD
        }))
        .await;

    let login_body: Value = login_response.json();
    let refresh_token = login_body["tokens"]["refresh_token"].as_str().unwrap();

    // Use refresh token to get new access token
    let refresh_response = server
        .post("/auth/refresh")
        .json(&json!({
            "refresh_token": refresh_token
        }))
        .await;

    refresh_response.assert_status(StatusCode::OK);
    let refresh_body: Value = refresh_response.json();
    assert_eq!(refresh_body["result"], "ok");
    assert!(refresh_body["access_token"].is_string());
    assert_eq!(refresh_body["user"]["username"], TEST_USERNAME);
}

#[tokio::test]
async fn test_refresh_token_invalid() {
    let server = create_test_server(default_config()).await;

    let response = server
        .post("/auth/refresh")
        .json(&json!({
            "refresh_token": "invalid_token"
        }))
        .await;

    response.assert_status(StatusCode::UNAUTHORIZED);
    let body: Value = response.json();
    assert_eq!(body["result"], "error");
}

#[tokio::test]
async fn test_revoke_token_success() {
    let server = create_test_server(default_config()).await;

    // Login to get tokens
    let login_response = server
        .post("/auth/login")
        .json(&json!({
            "username": TEST_USERNAME,
            "password": TEST_PASSWORD
        }))
        .await;

    let login_body: Value = login_response.json();
    let refresh_token = login_body["tokens"]["refresh_token"].as_str().unwrap();

    // Revoke the refresh token
    let revoke_response = server
        .post("/auth/revoke")
        .json(&json!({
            "refresh_token": refresh_token
        }))
        .await;

    revoke_response.assert_status(StatusCode::OK);
    let revoke_body: Value = revoke_response.json();
    assert_eq!(revoke_body["result"], "ok");

    // Try to use the revoked token - should fail
    let refresh_response = server
        .post("/auth/refresh")
        .json(&json!({
            "refresh_token": refresh_token
        }))
        .await;

    refresh_response.assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_logout_success() {
    let server = create_test_server(default_config()).await;

    // Login to get tokens
    let login_response = server
        .post("/auth/login")
        .json(&json!({
            "username": TEST_USERNAME,
            "password": TEST_PASSWORD
        }))
        .await;

    let login_body: Value = login_response.json();
    let access_token = login_body["tokens"]["access_token"].as_str().unwrap();
    let refresh_token = login_body["tokens"]["refresh_token"].as_str().unwrap();

    // Logout
    let logout_response = server
        .get("/auth/logout")
        .add_header(header::AUTHORIZATION, format!("Bearer {access_token}"))
        .await;

    logout_response.assert_status(StatusCode::OK);
    let logout_body: Value = logout_response.json();
    assert_eq!(logout_body["result"], "ok");

    // Try to use refresh token after logout - should fail
    let refresh_response = server
        .post("/auth/refresh")
        .json(&json!({
            "refresh_token": refresh_token
        }))
        .await;

    refresh_response.assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_protected_route_with_valid_token() {
    let server = create_test_server(default_config()).await;

    // Login to get access token
    let login_response = server
        .post("/auth/login")
        .json(&json!({
            "username": TEST_USERNAME,
            "password": TEST_PASSWORD
        }))
        .await;

    let login_body: Value = login_response.json();
    let access_token = login_body["tokens"]["access_token"].as_str().unwrap();

    // Access protected route
    let api_response = server
        .get("/api")
        .add_header(header::AUTHORIZATION, format!("Bearer {access_token}"))
        .await;

    api_response.assert_status(StatusCode::OK);
}

#[tokio::test]
async fn test_protected_route_without_token() {
    let server = create_test_server(default_config()).await;
    let response = server.get("/api").await;
    response.assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_protected_route_with_invalid_token() {
    let server = create_test_server(default_config()).await;

    let response = server
        .get("/api")
        .add_header(header::AUTHORIZATION, "Bearer invalid_token")
        .await;

    response.assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_access_token_expiry() {
    // Create config with very short token expiry
    let config = core::Config {
        jwt: core::JwtConfig {
            secret: "test_secret_key_for_testing_only".to_string(),
            access_token_expiry: 1, // 1 second
            refresh_token_expiry: 86400,
        },
        ..Default::default()
    };

    let server = create_test_server(config).await;

    // Login
    let login_response = server
        .post("/auth/login")
        .json(&json!({
            "username": TEST_USERNAME,
            "password": TEST_PASSWORD
        }))
        .await;

    let login_body: Value = login_response.json();
    let access_token = login_body["tokens"]["access_token"].as_str().unwrap();

    // Test token works before expiry
    let response_before = server
        .get("/api")
        .add_header(header::AUTHORIZATION, format!("Bearer {access_token}"))
        .await;
    response_before.assert_status(StatusCode::OK);

    // Wait for token to expire (longer wait to ensure expiration)
    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

    // Try to use expired token
    let response = server
        .get("/api")
        .add_header(header::AUTHORIZATION, format!("Bearer {access_token}"))
        .await;

    response.assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_malformed_json_login() {
    let server = create_test_server(default_config()).await;

    let response = server.post("/auth/login").text("not json").await;

    response.assert_status(StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn test_missing_fields_login() {
    let server = create_test_server(default_config()).await;

    let response = server
        .post("/auth/login")
        .json(&json!({
            "username": TEST_USERNAME
            // missing password
        }))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}
