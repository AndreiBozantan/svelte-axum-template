use axum::body::Body;
use axum::http;
use axum::http::HeaderValue;
use axum::http::Request;
use axum::http::StatusCode;
use axum::http::header;
use axum_test::TestServer;
use serde_json::Value;
use serde_json::json;
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::sqlite::SqlitePoolOptions;
use std::str::FromStr;

use crate::common::ArcContext;
use crate::common::Context;
use crate::config;
use crate::identity::auth::util::hash_password;
use crate::identity::users::repo::SqliteUserRepo;
use crate::identity::users::service::{CreateUserCommand, Email, TenantId, UserService, UserStatus};
use crate::internal::tokens;
use crate::jwt;
use crate::migrations;

const TEST_USER_EMAIL: &str = "test@example.com";
const TEST_PASSWORD: &str = "abcdefghijklmnopqrstuvwxyz";

fn default_config() -> config::AppSettings {
    config::AppSettings {
        jwt: config::JwtSettings {
            access_token_expiry_minutes: 60,
            refresh_token_expiry_days: 1,
        },
        server: config::ServerSettings {
            env: crate::constants::env::TEST.to_string(),
            ..Default::default()
        },
        ..Default::default()
    }
}

async fn create_test_context(config: config::AppSettings) -> anyhow::Result<ArcContext> {
    let db_config = config::DatabaseSettings {
        url: "sqlite::memory:".to_string(),
        max_connections: 5,
        store_temp_tables_in_memory: true,
    };
    let options = SqliteConnectOptions::from_str(&db_config.url)?
        .create_if_missing(true)
        .foreign_keys(true);
    let db = SqlitePoolOptions::new()
        .max_connections(db_config.max_connections)
        .connect_with(options)
        .await?;

    let jwt_secret = "test__secret__key__for__jwt__testing";
    let jwt = jwt::JwtContext::new(&config.jwt, jwt_secret)?;
    let http_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let ctx = Context::new(db, jwt, config, http_client).into();
    migrations::run_migrations(&ctx).await?;
    Ok(ctx)
}

async fn create_test_server(config: config::AppSettings) -> anyhow::Result<TestServer> {
    let ctx = create_test_context(config).await?;
    let password_hash = hash_password(TEST_PASSWORD)?;
    UserService::new(SqliteUserRepo)
        .create_user(
            &ctx.db,
            CreateUserCommand {
                tenant_id: TenantId(0),
                status: UserStatus::Active,
                email: Email::parse(TEST_USER_EMAIL)?,
                first_name: Some("Test".to_string()),
                middle_name: None,
                last_name: Some("User".to_string()),
                password_hash: Some(password_hash),
                sso_provider: None,
                sso_id: None,
            },
        )
        .await?;

    let platform_router = crate::identity::router(ctx.clone())
        .with_state(ctx);
    let api_router = axum::Router::new().nest("/api", platform_router);
    Ok(TestServer::new(
        api_router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    ))
}

async fn login_and_get_tokens(
    server: &TestServer,
    email: &str,
    password: &str,
) -> anyhow::Result<(Value, String, String)> {
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
    Ok((body, access_token, refresh_token))
}

async fn login_testuser_and_get_tokens(server: &TestServer) -> anyhow::Result<(Value, String, String)> {
    let (body, access_token, refresh_token) = login_and_get_tokens(server, TEST_USER_EMAIL, TEST_PASSWORD).await?;
    assert!(!access_token.is_empty());
    assert!(!refresh_token.is_empty());
    Ok((body, access_token, refresh_token))
}

#[tokio::test]
async fn login_invalid_endpoint() -> anyhow::Result<()> {
    let server = create_test_server(default_config()).await?;
    let response = server
        .post("/api/invalid_endpoint")
        .json(&json!({
            "email": TEST_USER_EMAIL,
            "password": "wrong_password"
        }))
        .await;
    response.assert_status(StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
async fn login_invalid_credentials() -> anyhow::Result<()> {
    let server = create_test_server(default_config()).await?;
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
    Ok(())
}

#[tokio::test]
async fn login_nonexistent_user() -> anyhow::Result<()> {
    let server = create_test_server(default_config()).await?;
    let response = server
        .post("/api/auth/login")
        .json(&json!({
            "email": "nonexistent@example.com",
            "password": "password"
        }))
        .await;
    response.assert_status(StatusCode::UNAUTHORIZED);
    let body: Value = response.json();
    assert_eq!(body["code"], "invalid_credentials");
    Ok(())
}

#[tokio::test]
async fn refresh_token_invalid() -> anyhow::Result<()> {
    let server = create_test_server(default_config()).await?;
    let response = server.post("/api/auth/refresh").await;
    response.assert_status(StatusCode::UNAUTHORIZED);
    let body: Value = response.json();
    assert_eq!(body["code"], "invalid_token");
    Ok(())
}

#[tokio::test]
async fn protected_route_without_token() -> anyhow::Result<()> {
    let server = create_test_server(default_config()).await?;
    let response = server.get("/api/users/me").await;
    response.assert_status(StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn protected_route_with_invalid_token() -> anyhow::Result<()> {
    let server = create_test_server(default_config()).await?;
    let response = server
        .get("/api/users/me")
        .add_header(header::AUTHORIZATION, "Bearer invalid_token")
        .await;
    response.assert_status(StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn login_success() -> anyhow::Result<()> {
    let server = create_test_server(default_config()).await?;
    let (body, access_token, refresh_token) = login_testuser_and_get_tokens(&server).await?;
    assert!(!access_token.is_empty());
    assert!(!refresh_token.is_empty());
    assert_eq!(body["user"]["email"], TEST_USER_EMAIL);
    Ok(())
}

#[tokio::test]
async fn malformed_json_login() -> anyhow::Result<()> {
    let server = create_test_server(default_config()).await?;
    let response = server.post("/api/auth/login").text("not json").await;
    response.assert_status(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    Ok(())
}

#[tokio::test]
async fn missing_fields_login() -> anyhow::Result<()> {
    let server = create_test_server(default_config()).await?;
    let response = server
        .post("/api/auth/login")
        .json(&json!({ "email": TEST_USER_EMAIL }))
        .await;
    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
    Ok(())
}

#[tokio::test]
async fn refresh_token_success() -> anyhow::Result<()> {
    let server = create_test_server(default_config()).await?;
    let (_body, _access_token, refresh_token) = login_testuser_and_get_tokens(&server).await?;
    let refresh_response = server
        .post("/api/auth/refresh")
        .add_cookie(cookie::Cookie::new("refresh_token", refresh_token.clone()))
        .await;
    refresh_response.assert_status(StatusCode::OK);
    let refresh_body: Value = refresh_response.json();
    assert!(!refresh_response.cookie("access_token").value().is_empty());
    assert_eq!(refresh_body["user"]["email"], TEST_USER_EMAIL);
    Ok(())
}

#[tokio::test]
async fn revoke_token_success() -> anyhow::Result<()> {
    let settings = default_config();
    let server = create_test_server(settings.clone()).await?;
    let (_body, _access_token, refresh_token) = login_testuser_and_get_tokens(&server).await?;
    let revoke_response = server
        .post("/api/auth/refresh")
        .add_cookie(cookie::Cookie::new("refresh_token", refresh_token.clone()))
        .await;
    revoke_response.assert_status(StatusCode::OK);
    let revoke_body: Value = revoke_response.json();
    assert_eq!(revoke_body["expires_in"], settings.jwt.access_token_expiry_minutes * 60);

    let refresh_response = server
        .post("/api/auth/refresh")
        .add_cookie(cookie::Cookie::new("refresh_token", refresh_token.clone()))
        .await;
    refresh_response.assert_status(StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn logout_success() -> anyhow::Result<()> {
    let server = create_test_server(default_config()).await?;
    let (_body, _access_token, refresh_token) = login_testuser_and_get_tokens(&server).await?;
    let logout_response = server
        .post("/api/auth/logout")
        .add_cookie(cookie::Cookie::new("refresh_token", refresh_token.clone()))
        .await;
    logout_response.assert_status(StatusCode::NO_CONTENT);

    let refresh_response = server
        .post("/api/auth/refresh")
        .add_cookie(cookie::Cookie::new("refresh_token", refresh_token.clone()))
        .await;
    refresh_response.assert_status(StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn protected_route_with_valid_token() -> anyhow::Result<()> {
    let server = create_test_server(default_config()).await?;
    let (_body, access_token, _refresh_token) = login_testuser_and_get_tokens(&server).await?;
    let api_response = server
        .get("/api/users/me")
        .add_cookie(cookie::Cookie::new("access_token", access_token.clone()))
        .await;
    api_response.assert_status(StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn access_token_expiry() -> anyhow::Result<()> {
    use chrono::Utc;
    use jsonwebtoken as jwtk;
    use uuid::Uuid;

    let server = create_test_server(default_config()).await?;
    let login_response = server
        .post("/api/auth/login")
        .json(&json!({
            "email": TEST_USER_EMAIL,
            "password": TEST_PASSWORD
        }))
        .await;
    let valid_access_token = login_response.cookie("access_token").value().to_string();

    let response_valid = server
        .get("/api/users/me")
        .add_cookie(cookie::Cookie::new("access_token", valid_access_token.clone()))
        .await;
    response_valid.assert_status(StatusCode::OK);

    let jwt_settings = config::JwtSettings {
        access_token_expiry_minutes: 60,
        refresh_token_expiry_days: 1,
    };
    let jwt_secret = "test__secret__key__for__jwt__testing";
    let jwt_context = jwt::JwtContext::new(&jwt_settings, jwt_secret)?;

    let now = Utc::now().timestamp();
    let expired_time = now - 3600;
    let header = jwtk::Header::new(jwtk::Algorithm::HS256);
    let expired_claims = jwt::TokenClaims {
        sub: "1".to_string(),
        tenant_id: 0,
        email: TEST_USER_EMAIL.to_string(),
        exp: expired_time,
        iat: expired_time - 3600,
        jti: Uuid::new_v4().to_string(),
        token_type: jwt::TokenType::Access,
    };
    let expired_token = jwtk::encode(&header, &expired_claims, &jwt_context.encoding_key)?;

    let response_expired = server
        .get("/api/users/me")
        .add_cookie(cookie::Cookie::new("access_token", expired_token))
        .await;
    response_expired.assert_status(StatusCode::UNAUTHORIZED);
    let body: Value = response_expired.json();
    assert_eq!(body["code"], "expired_token");
    Ok(())
}

#[tokio::test]
async fn decode_access_token_from_req_cookie_success() -> anyhow::Result<()> {
    let ctx = create_test_context(default_config()).await?;
    let token = jwt::generate_token(&ctx.jwt, 123, 0, "test_user", jwt::TokenType::Access, 1)?;
    let mut req = Request::new(Body::empty());
    req.headers_mut().insert(
        http::header::COOKIE,
        HeaderValue::from_str(&format!("access_token={}", token.value))?,
    );
    let claims = tokens::decode_token_from_req(&ctx, &req, jwt::TokenType::Access)?;
    assert_eq!(claims.sub, "123");
    assert_eq!(claims.email, "test_user");
    Ok(())
}

#[tokio::test]
async fn decode_access_token_from_req_success() -> anyhow::Result<()> {
    let ctx = create_test_context(default_config()).await?;
    let token = jwt::generate_token(&ctx.jwt, 123, 0, "test_user", jwt::TokenType::Access, 1)?;
    let mut req = Request::new(Body::empty());
    req.headers_mut().insert(
        http::header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {}", token.value))?,
    );
    let claims = tokens::decode_token_from_req(&ctx, &req, jwt::TokenType::Access)?;
    assert_eq!(claims.sub, "123");
    assert_eq!(claims.email, "test_user");
    Ok(())
}

#[tokio::test]
async fn decode_access_token_from_req_missing_header() -> anyhow::Result<()> {
    let ctx = create_test_context(default_config()).await?;
    let req = Request::new(Body::empty());
    assert!(tokens::decode_token_from_req(&ctx, &req, jwt::TokenType::Access).is_err());
    Ok(())
}

#[tokio::test]
async fn decode_access_token_from_req_wrong_format() -> anyhow::Result<()> {
    let ctx = create_test_context(default_config()).await?;
    let mut req = Request::new(Body::empty());
    req.headers_mut()
        .insert(http::header::AUTHORIZATION, HeaderValue::from_str("some_token")?);
    assert!(tokens::decode_token_from_req(&ctx, &req, jwt::TokenType::Access).is_err());
    Ok(())
}

#[tokio::test]
async fn account_lockout_after_failed_attempts() -> anyhow::Result<()> {
    let server = create_test_server(default_config()).await?;
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
    let response = server
        .post("/api/auth/login")
        .json(&json!({
            "email": TEST_USER_EMAIL,
            "password": TEST_PASSWORD
        }))
        .await;
    response.assert_status(StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn user_info_unauthenticated_returns_401() -> anyhow::Result<()> {
    let server = create_test_server(default_config()).await?;
    let response = server.get("/api/users/me").await;
    response.assert_status(StatusCode::UNAUTHORIZED);
    let body: Value = response.json();
    assert_eq!(body["code"], "invalid_token");
    Ok(())
}
