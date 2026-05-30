use axum::body::Body;
use axum::http;
use axum::http::HeaderValue;
use axum::http::Request;
use axum::http::StatusCode;
use axum::http::header;
use axum_test::TestServer;
use serde_json::Value;
use serde_json::json;

use platform::common::ArcContext;
use platform::common::Context;
use platform::config;
use platform::db;
use platform::jwt;
use platform::password;
use platform::tokens;
use platform::migrations;

use platform::models;
use platform::queries;

const TEST_USER_EMAIL: &str = "test@example.com";
const TEST_PASSWORD: &str = "abcdefghijklmnopqrstuvwxyz";

fn default_config() -> config::AppSettings {
    config::AppSettings {
        jwt: config::JwtSettings {
            access_token_expiry_minutes: 60,
            refresh_token_expiry_days: 1,
        },
        ..Default::default()
    }
}

async fn create_test_context(config: config::AppSettings) -> ArcContext {
    // use a temporary in-memory SQLite database for testing
    let db_config = config::DatabaseSettings {
        url: "sqlite::memory:".to_string(),
        max_connections: 5,
        store_temp_tables_in_memory: true,
    };
    let db = db::create_context(&db_config).await.unwrap();

    let jwt_secret = "test__secret__key__for__jwt__testing";
    let jwt = jwt::JwtContext::new(&config.jwt, jwt_secret).unwrap();

    let http_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Failed to create HTTP client");

let ctx = Context::new(db, jwt, config, http_client);

    migrations::run_migrations(&ctx).await.unwrap();

    ctx
}

async fn create_test_server(config: config::AppSettings) -> TestServer {
    let ctx = create_test_context(config).await;
    let password_hash = password::hash_password(TEST_PASSWORD).unwrap();
    let user = models::NewUser {
        tenant_id: 0,
        status: models::UserStatus::Active,
        email: "test@example.com".to_string(),
        first_name: "Test".to_string().into(),
        middle_name: None,
        last_name: "User".to_string().into(),
        password_hash: Some(password_hash),
        sso_provider: None,
        sso_id: None,
    };
    queries::create_user(&ctx.db, user).await.unwrap();
    let platform_router = platform::routes::create(ctx.clone()).with_state(ctx);
    let api_router = axum::Router::new().nest("/api", platform_router);
    TestServer::new(api_router.into_make_service_with_connect_info::<std::net::SocketAddr>())
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
    assert_eq!(body["code"], "invalid_credentials");
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
    assert_eq!(body["code"], "invalid_credentials");
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
    assert_eq!(body["code"], "invalid_token");
}

#[tokio::test]
async fn test_protected_route_without_token() {
    let server = create_test_server(default_config()).await;
    let response = server.get("/api/users/me").await;
    response.assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_protected_route_with_invalid_token() {
    let server = create_test_server(default_config()).await;

    let response = server
        .get("/api/users/me")
        .add_header(header::AUTHORIZATION, "Bearer invalid_token")
        .await;

    response.assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_login_success() {
    let server = create_test_server(default_config()).await;
    let (body, access_token, refresh_token) = login_testuser_and_get_tokens(&server).await;
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
    assert!(!refresh_response.cookie("access_token").value().is_empty());
    assert_eq!(refresh_body["user"]["email"], TEST_USER_EMAIL);
}

#[tokio::test]
async fn test_revoke_token_success() {
    let settings = default_config();
    let server = create_test_server(settings.clone()).await;
    let (_body, _access_token, refresh_token) = login_testuser_and_get_tokens(&server).await;

    // refresh will revoke the refresh token
    let revoke_response = server
        .post("/api/auth/refresh")
        .add_cookie(cookie::Cookie::new("refresh_token", refresh_token.clone()))
        .await;

    revoke_response.assert_status(StatusCode::OK);
    let revoke_body: Value = revoke_response.json();
    assert_eq!(revoke_body["expires_in"], settings.jwt.access_token_expiry_minutes * 60);

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
    let (_body, _access_token, refresh_token) = login_testuser_and_get_tokens(&server).await;

    // logout
    let logout_response = server
        .post("/api/auth/logout")
        .add_cookie(cookie::Cookie::new("refresh_token", refresh_token.clone()))
        .await;

    logout_response.assert_status(StatusCode::NO_CONTENT);

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
        .get("/api/users/me")
        .add_cookie(cookie::Cookie::new("access_token", access_token.clone()))
        .await;

    api_response.assert_status(StatusCode::OK);
}

#[tokio::test]
async fn test_access_token_expiry() {
    // instead of using sleep and waiting for tokens to expire (which is slow and flaky),
    // we manually create expired tokens with past timestamps for fast, deterministic testing
    use chrono::Utc;
    use jsonwebtoken as jwtk;
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
        .get("/api/users/me")
        .add_cookie(cookie::Cookie::new("access_token", valid_access_token.clone()))
        .await;
    response_valid.assert_status(StatusCode::OK);

    // now create an expired token manually using the same JWT context setup as the server
    let jwt_settings = config::JwtSettings {
        access_token_expiry_minutes: 60,
        refresh_token_expiry_days: 1,
    };
    let jwt_secret = "test__secret__key__for__jwt__testing";
    let jwt_context = jwt::JwtContext::new(&jwt_settings, jwt_secret).unwrap();

    // create an expired access token by setting past timestamps
    let now = Utc::now().timestamp();
    let expired_time = now - 3600; // 1 hour ago

    let header = jwtk::Header::new(jwtk::Algorithm::HS256);
    let expired_claims = jwt::TokenClaims {
        sub: "1".to_string(), // user ID from our test user
        tenant_id: 1,
        email: TEST_USER_EMAIL.to_string(),
        exp: expired_time,        // expired timestamp
        iat: expired_time - 3600, // issued 2 hours ago
        jti: Uuid::new_v4().to_string(),
        token_type: jwt::TokenType::Access,
    };

    let expired_token = jwtk::encode(&header, &expired_claims, &jwt_context.encoding_key).unwrap();

    // test that expired token is rejected
    let response_expired = server
        .get("/api/users/me")
        .add_cookie(cookie::Cookie::new("access_token", expired_token))
        .await;
    response_expired.assert_status(StatusCode::UNAUTHORIZED);
    let body: Value = response_expired.json();
    assert_eq!(body["code"], "expired_token");
}

#[tokio::test]
async fn test_decode_access_token_from_req_cookie_success() {
    let ctx = create_test_context(default_config()).await;
    let user_id = 123;
    let email = "test_user";
    let token = jwt::generate_token(&ctx.jwt, user_id, 0, email, jwt::TokenType::Access, 1).unwrap();
    let mut req = Request::new(Body::empty());
    req.headers_mut().insert(
        http::header::COOKIE,
        HeaderValue::from_str(&format!("access_token={}", token.value)).unwrap(),
    );
    let claims = tokens::decode_token_from_req(&ctx, &req, jwt::TokenType::Access).unwrap();
    assert_eq!(claims.sub, user_id.to_string());
    assert_eq!(claims.email, email);
}

#[tokio::test]
async fn test_decode_access_token_from_req_success() {
    let ctx = create_test_context(default_config()).await;
    let user_id = 123;
    let email = "test_user";

    let token = jwt::generate_token(&ctx.jwt, user_id, 0, email, jwt::TokenType::Access, 1).unwrap();

    let mut req = Request::new(Body::empty());
    req.headers_mut().insert(
        http::header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {}", token.value)).unwrap(),
    );

    let claims = tokens::decode_token_from_req(&ctx, &req, jwt::TokenType::Access).unwrap();
    assert_eq!(claims.sub, user_id.to_string());
    assert_eq!(claims.email, email);
}

#[tokio::test]
async fn test_decode_access_token_from_req_missing_header() {
    let ctx = create_test_context(default_config()).await;
    let req = Request::new(Body::empty());

    let result = tokens::decode_token_from_req(&ctx, &req, jwt::TokenType::Access);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), tokens::TokenError::TokenInvalid));
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

    let result = tokens::decode_token_from_req(&ctx, &req, jwt::TokenType::Access);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), tokens::TokenError::TokenInvalid));
}

#[tokio::test]
async fn test_account_lockout_after_failed_attempts() {
    let server = create_test_server(default_config()).await;

    for _ in 0..5 {
        let response = server
            .post("/api/auth/login")
            .json(&json!({
                "email": TEST_USER_EMAIL,
                "password": "wrong_password"
            }))
            .await;
        response.assert_status(StatusCode::UNAUTHORIZED);
    }

    // correct password on the 6th attempt — should still be rejected
    let response = server
        .post("/api/auth/login")
        .json(&json!({
            "email": TEST_USER_EMAIL,
            "password": TEST_PASSWORD
        }))
        .await;
    response.assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_user_info_unauthenticated_returns_401() {
    let server = create_test_server(default_config()).await;

    let response = server.get("/api/users/me").await;

    response.assert_status(StatusCode::UNAUTHORIZED);
    let body: Value = response.json();
    assert_eq!(body["code"], "invalid_token");
}
