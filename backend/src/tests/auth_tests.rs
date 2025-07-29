use axum::http::StatusCode;
use axum::http::header;
use axum_test::TestServer;
use serde_json::Value;
use serde_json::json;

use crate::app;
use crate::auth;
use crate::cfg;
use crate::core;
use crate::db;

const TEST_PASSWORD: &str = "abcdefghijklmnopqrstuvwxyz";
const TEST_USERNAME: &str = "test_user";

fn default_config() -> cfg::AppSettings {
    cfg::AppSettings {
        jwt: cfg::JwtSettings {
            access_token_expiry: 3600,
            refresh_token_expiry: 86400,
        },
        ..Default::default()
    }
}
async fn create_test_server(config: cfg::AppSettings) -> TestServer {
    let mut config = config.clone();

    // use a temporary in-memory SQLite database file and use it for testing
    config.database = cfg::DatabaseSettings {
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

    let jwt_secret = "test__secret__key__for__jwt__testing";
    let jwt = auth::JwtContext::new(&config.jwt, jwt_secret).unwrap();
    let http_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Failed to create HTTP client");

    let context = core::Context::new(db, jwt, http_client, config);
    db::create_user(&context.db, user).await.unwrap();

    let router = app::create_router(context);
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
    // Instead of using sleep and waiting for tokens to expire (which is slow and flaky),
    // we manually create expired tokens with past timestamps for fast, deterministic testing
    use chrono::Utc;
    use jsonwebtoken as jwt;
    use uuid::Uuid;

    let server = create_test_server(default_config()).await;

    // First, login to verify the endpoint works with valid tokens
    let login_response = server
        .post("/auth/login")
        .json(&json!({
            "username": TEST_USERNAME,
            "password": TEST_PASSWORD
        }))
        .await;

    let login_body: Value = login_response.json();
    let valid_access_token = login_body["tokens"]["access_token"].as_str().unwrap();

    // Test that a valid token works
    let response_valid = server
        .get("/api")
        .add_header(header::AUTHORIZATION, format!("Bearer {valid_access_token}"))
        .await;
    response_valid.assert_status(StatusCode::OK);

    // Now create an expired token manually using the same JWT context setup as the server
    let jwt_settings = cfg::JwtSettings {
        access_token_expiry: 3600,
        refresh_token_expiry: 86400,
    };
    let jwt_secret = "test__secret__key__for__jwt__testing";
    let jwt_context = auth::JwtContext::new(&jwt_settings, jwt_secret).unwrap();

    // Create an expired access token by setting past timestamps
    let now = Utc::now().timestamp();
    let expired_time = now - 3600; // 1 hour ago

    let header = jwt::Header::new(jwt::Algorithm::HS256);
    let expired_claims = auth::AccessTokenClaims {
        sub: "1".to_string(), // User ID from our test user
        username: TEST_USERNAME.to_string(),
        tenant_id: Some(1),
        exp: expired_time, // Expired timestamp
        iat: expired_time - 3600, // Issued 2 hours ago
        jti: Uuid::new_v4().to_string(),
        token_type: auth::TokenType::Access,
    };

    let expired_token = jwt::encode(&header, &expired_claims, &jwt_context.encoding_key).unwrap();

    // Test that expired token is rejected
    let response_expired = server
        .get("/api")
        .add_header(header::AUTHORIZATION, format!("Bearer {expired_token}"))
        .await;

    response_expired.assert_status(StatusCode::UNAUTHORIZED);
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
