use axum::body::Body;
use axum::http;
use axum::http::HeaderValue;
use axum::http::Request;
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

const TEST_USER_EMAIL: &str = "test@example.com";
const TEST_PASSWORD: &str = "abcdefghijklmnopqrstuvwxyz";

fn default_config() -> cfg::AppSettings {
    cfg::AppSettings {
        jwt: cfg::JwtSettings {
            access_token_expiry_minutes: 60,
            refresh_token_expiry_days: 1,
        },
        ..Default::default()
    }
}

async fn create_test_context(config: cfg::AppSettings) -> core::ArcContext {
    // use a temporary in-memory SQLite database for testing
    let db_config = cfg::DatabaseSettings {
        url: "sqlite::memory:".to_string(),
        max_connections: 5,
    };
    let db = app::create_db_context(&db_config).await.unwrap();
    app::run_migrations(&db).await.unwrap();

    let jwt_secret = "test__secret__key__for__jwt__testing";
    let jwt = auth::JwtContext::new(&config.jwt, jwt_secret).unwrap();

    let http_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Failed to create HTTP client");

    core::Context::new(db, jwt, http_client, config)
}

async fn create_test_server(config: cfg::AppSettings) -> TestServer {
    let ctx = create_test_context(config).await;

    // create test user
    let password_hash = auth::hash_password(TEST_PASSWORD).unwrap();
    let user = db::NewUser {
        tenant_id: 0,
        email: "test@example.com".to_string(),
        password_hash: Some(password_hash),
        sso_provider: None,
        sso_id: None,
    };
    db::create_user(&ctx.db, user).await.unwrap();

    let router = app::create_router(ctx);
    TestServer::new(router.into_make_service_with_connect_info::<std::net::SocketAddr>()).unwrap()
}

async fn login_and_get_tokens(server: &TestServer, email: &str, password: &str) -> (Value, String, String) {
    let response = server
        .post("/api/auth/login")
        .json(&json!({
            "email": email,
            "password": password
        }))
        .await;

    response.assert_status(StatusCode::OK);
    let body: Value = response.json();
    let refresh_token = response.cookie("refresh_token").value().to_string();
    let access_token = response.cookie("access_token").value().to_string();
    (body, access_token, refresh_token)
}

async fn login_testuser_and_get_tokens(server: &TestServer) -> (Value, String, String) {
    let (body, access_token, refresh_token) = login_and_get_tokens(server, TEST_USER_EMAIL, TEST_PASSWORD).await;
    assert!(!access_token.is_empty());
    assert!(!refresh_token.is_empty());
    (body, access_token, refresh_token)
}

#[tokio::test]
async fn test_login_invalid_endpoint() {
    let server = create_test_server(default_config()).await;

    let response = server
        .post("/api/invalid_endpoint")
        .json(&json!({
            "email": TEST_USER_EMAIL,
            "password": "wrong_password"
        }))
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_login_invalid_credentials() {
    let server = create_test_server(default_config()).await;

    let response = server
        .post("/api/auth/login")
        .json(&json!({
            "email": TEST_USER_EMAIL,
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
        .post("/api/auth/login")
        .json(&json!({
            "email": "nonexistent",
            "password": "password"
        }))
        .await;

    response.assert_status(StatusCode::UNAUTHORIZED);
    let body: Value = response.json();
    assert_eq!(body["result"], "error");
}

#[tokio::test]
async fn test_refresh_token_invalid() {
    let server = create_test_server(default_config()).await;

    let response = server
        .post("/api/auth/refresh")
        .json(&json!({
            "refresh_token": "invalid_token"
        }))
        .await;

    response.assert_status(StatusCode::UNAUTHORIZED);
    let body: Value = response.json();
    assert_eq!(body["result"], "error");
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
async fn test_login_success() {
    let server = create_test_server(default_config()).await;
    let (body, access_token, refresh_token) = login_testuser_and_get_tokens(&server).await;
    assert_eq!(body["result"], "ok");
    assert!(!access_token.is_empty());
    assert!(!refresh_token.is_empty());
    assert_eq!(body["user"]["email"], TEST_USER_EMAIL);
}

#[tokio::test]
async fn test_malformed_json_login() {
    let server = create_test_server(default_config()).await;

    let response = server.post("/api/auth/login").text("not json").await;

    response.assert_status(StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn test_missing_fields_login() {
    let server = create_test_server(default_config()).await;

    let response = server
        .post("/api/auth/login")
        .json(&json!({
            "email": TEST_USER_EMAIL
            // missing password
        }))
        .await;

    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn test_refresh_token_success() {
    let server = create_test_server(default_config()).await;
    let (_body, _access_token, refresh_token) = login_testuser_and_get_tokens(&server).await;

    // use refresh token to get new access token
    let refresh_response = server
        .post("/api/auth/refresh")
        .add_cookie(cookie::Cookie::new("refresh_token", refresh_token.clone()))
        .await;

    refresh_response.assert_status(StatusCode::OK);
    let refresh_body: Value = refresh_response.json();
    assert_eq!(refresh_body["result"], "ok");
    assert!(!refresh_response.cookie("access_token").value().is_empty());
    assert_eq!(refresh_body["user"]["email"], TEST_USER_EMAIL);
}

#[tokio::test]
async fn test_revoke_token_success() {
    let server = create_test_server(default_config()).await;
    let (_body, _access_token, refresh_token) = login_testuser_and_get_tokens(&server).await;

    // revoke the refresh token
    let revoke_response = server
        .post("/api/auth/refresh/revoke")
        .add_cookie(cookie::Cookie::new("refresh_token", refresh_token.clone()))
        .await;

    revoke_response.assert_status(StatusCode::OK);
    let revoke_body: Value = revoke_response.json();
    assert_eq!(revoke_body["result"], "ok");

    // try to use the revoked token - should fail
    let refresh_response = server
        .post("/api/auth/refresh")
        .add_cookie(cookie::Cookie::new("refresh_token", refresh_token.clone()))
        .await;

    refresh_response.assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_logout_success() {
    let server = create_test_server(default_config()).await;
    let (_body, access_token, refresh_token) = login_testuser_and_get_tokens(&server).await;

    // logout
    let logout_response = server
        .get("/api/auth/logout")
        .add_cookie(cookie::Cookie::new("access_token", access_token.clone()))
        .await;

    logout_response.assert_status(StatusCode::OK);
    let logout_body: Value = logout_response.json();
    assert_eq!(logout_body["result"], "ok");

    // try to use refresh token after logout - should fail
    let refresh_response = server
        .post("/api/auth/refresh")
        .add_cookie(cookie::Cookie::new("refresh_token", refresh_token.clone()))
        .await;

    refresh_response.assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_protected_route_with_valid_token() {
    let server = create_test_server(default_config()).await;
    let (_body, access_token, _refresh_token) = login_testuser_and_get_tokens(&server).await;

    // access protected route
    let api_response = server
        .get("/api")
        .add_cookie(cookie::Cookie::new("access_token", access_token.clone()))
        .await;

    api_response.assert_status(StatusCode::OK);
}

#[tokio::test]
async fn test_access_token_expiry() {
    // instead of using sleep and waiting for tokens to expire (which is slow and flaky),
    // we manually create expired tokens with past timestamps for fast, deterministic testing
    use chrono::Utc;
    use jsonwebtoken as jwt;
    use uuid::Uuid;

    let server = create_test_server(default_config()).await;

    // first, login to verify the endpoint works with valid tokens
    let login_response = server
        .post("/api/auth/login")
        .json(&json!({
            "email": TEST_USER_EMAIL,
            "password": TEST_PASSWORD
        }))
        .await;

    let valid_access_token = login_response.cookie("access_token").value().to_string();

    // test that a valid token works
    let response_valid = server
        .get("/api")
        .add_cookie(cookie::Cookie::new("access_token", valid_access_token.clone()))
        .await;
    response_valid.assert_status(StatusCode::OK);

    // now create an expired token manually using the same JWT context setup as the server
    let jwt_settings = cfg::JwtSettings {
        access_token_expiry_minutes: 60,
        refresh_token_expiry_days: 1,
    };
    let jwt_secret = "test__secret__key__for__jwt__testing";
    let jwt_context = auth::JwtContext::new(&jwt_settings, jwt_secret).unwrap();

    // create an expired access token by setting past timestamps
    let now = Utc::now().timestamp();
    let expired_time = now - 3600; // 1 hour ago

    let header = jwt::Header::new(jwt::Algorithm::HS256);
    let expired_claims = auth::TokenClaims {
        sub: "1".to_string(), // user ID from our test user
        tenant_id: 1,
        email: TEST_USER_EMAIL.to_string(),
        exp: expired_time,        // expired timestamp
        iat: expired_time - 3600, // issued 2 hours ago
        jti: Uuid::new_v4().to_string(),
        token_type: auth::TokenType::Access,
    };

    let expired_token = jwt::encode(&header, &expired_claims, &jwt_context.encoding_key).unwrap();

    // test that expired token is rejected
    let response_expired = server
        .get("/api")
        .add_cookie(cookie::Cookie::new("access_token", expired_token))
        .await;

    response_expired.assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_decode_access_token_from_req_cookie_success() {
    let ctx = create_test_context(default_config()).await;
    let user_id = 123;
    let email = "test_user";
    let token = auth::generate_token(&ctx.jwt, user_id, 0, email, auth::TokenType::Access, 1).unwrap();
    let mut req = Request::new(Body::empty());
    req.headers_mut().insert(
        http::header::COOKIE,
        HeaderValue::from_str(&format!("access_token={}", token.value)).unwrap(),
    );
    let claims = auth::decode_token_from_req(&ctx, &req, auth::TokenType::Access).unwrap();
    assert_eq!(claims.sub, user_id.to_string());
    assert_eq!(claims.email, email);
}

#[tokio::test]
async fn test_decode_access_token_from_req_success() {
    let ctx = create_test_context(default_config()).await;
    let user_id = 123;
    let email = "test_user";

    let token = auth::generate_token(&ctx.jwt, user_id, 0, email, auth::TokenType::Access, 1).unwrap();

    let mut req = Request::new(Body::empty());
    req.headers_mut().insert(
        http::header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {}", token.value)).unwrap(),
    );

    let claims = auth::decode_token_from_req(&ctx, &req, auth::TokenType::Access).unwrap();
    assert_eq!(claims.sub, user_id.to_string());
    assert_eq!(claims.email, email);
}

#[tokio::test]
async fn test_decode_access_token_from_req_missing_header() {
    let ctx = create_test_context(default_config()).await;
    let req = Request::new(Body::empty());

    let result = auth::decode_token_from_req(&ctx, &req, auth::TokenType::Access);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), auth::TokenError::TokenInvalid));
}

#[tokio::test]
async fn test_decode_access_token_from_req_wrong_format() {
    let ctx = create_test_context(default_config()).await;
    let mut req = Request::new(Body::empty());

    // missing "Bearer " prefix
    req.headers_mut().insert(
        http::header::AUTHORIZATION,
        HeaderValue::from_str("some_token").unwrap(),
    );

    let result = auth::decode_token_from_req(&ctx, &req, auth::TokenType::Access);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), auth::TokenError::TokenInvalid));
}
