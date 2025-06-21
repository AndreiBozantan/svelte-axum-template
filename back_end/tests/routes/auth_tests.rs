use axum::middleware;
use axum::routing::get;
use axum::routing::post;
use axum::Router;
use tower_http::trace::TraceLayer;
use crate::appcontext::AppContext;
use crate::store::Store;
use crate::db::schema::{NewUser, NewTenant};
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum_test::TestServer;
use serde_json::{json, Value};
use sqlx::SqlitePool;
use tempfile::NamedTempFile;
use tokio;

use crate::{
    assets,
    middlewares, routes,
    appcontext::AppContext,
};

#[cfg(test)]
mod tests {
    use super::*;

    async fn create_test_context() -> AppContext {
        let temp_db = NamedTempFile::new().unwrap();
        let database_url = format!("sqlite:{}", temp_db.path().to_str().unwrap());

        let config = AppConfig {
            jwt: JwtConfig {
                secret: "test_secret_key_for_testing_only".to_string(),
                access_token_expiry: 3600,
                refresh_token_expiry: 86400,
            },
            database: DatabaseConfig {
                url: database_url.clone(),
            },
            ..Default::default()
        };

        let pool = SqlitePool::connect(&database_url).await.unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();

        let store = Store::new(pool);

        // Create test tenant
        let tenant = NewTenant {
            name: "Test Tenant".to_string(),
            description: Some("Test tenant for auth tests".to_string()),
        };
        let tenant_id = store.create_tenant(tenant).await.unwrap();

        // Create test user
        let password_hash = crate::routes::auth::hash_password("testpass123").unwrap();
        let user = NewUser {
            username: "testuser".to_string(),
            password_hash: Some(password_hash),
            email: Some("test@example.com".to_string()),
            tenant_id: Some(tenant_id),
            sso_provider: None,
            sso_id: None,
        };
        store.create_user(user).await.unwrap();

        AppContext::new(config, store)
    }

    #[tokio::test]
    async fn test_login_success() {
        let context = create_test_context().await;
        let app = backend(&context);
        let server = TestServer::new(app).unwrap();

        let response = server
            .post("/auth/login")
            .json(&json!({
                "username": "testuser",
                "password": "testpass123"
            }))
            .await;

        response.assert_status(StatusCode::OK);
        let body: Value = response.json();
        assert_eq!(body["result"], "ok");
        assert!(body["tokens"]["access_token"].is_string());
        assert!(body["tokens"]["refresh_token"].is_string());
        assert_eq!(body["user"]["username"], "testuser");
    }

    #[tokio::test]
    async fn test_login_invalid_credentials() {
        let context = create_test_context().await;
        let app = backend(&context);
        let server = TestServer::new(app).unwrap();

        let response = server
            .post("/auth/login")
            .json(&json!({
                "username": "testuser",
                "password": "wrongpassword"
            }))
            .await;

        response.assert_status(StatusCode::UNAUTHORIZED);
        let body: Value = response.json();
        assert_eq!(body["result"], "error");
    }

    #[tokio::test]
    async fn test_login_nonexistent_user() {
        let context = create_test_context().await;
        let app = backend(&context);
        let server = TestServer::new(app).unwrap();

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
        let context = create_test_context().await;
        let app = backend(&context);
        let server = TestServer::new(app).unwrap();

        // First login to get tokens
        let login_response = server
            .post("/auth/login")
            .json(&json!({
                "username": "testuser",
                "password": "testpass123"
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
        assert_eq!(refresh_body["user"]["username"], "testuser");
    }

    #[tokio::test]
    async fn test_refresh_token_invalid() {
        let context = create_test_context().await;
        let app = backend(&context);
        let server = TestServer::new(app).unwrap();

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
        let context = create_test_context().await;
        let app = backend(&context);
        let server = TestServer::new(app).unwrap();

        // Login to get tokens
        let login_response = server
            .post("/auth/login")
            .json(&json!({
                "username": "testuser",
                "password": "testpass123"
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
        let context = create_test_context().await;
        let app = backend(&context);
        let server = TestServer::new(app).unwrap();

        // Login to get tokens
        let login_response = server
            .post("/auth/login")
            .json(&json!({
                "username": "testuser",
                "password": "testpass123"
            }))
            .await;

        let login_body: Value = login_response.json();
        let access_token = login_body["tokens"]["access_token"].as_str().unwrap();
        let refresh_token = login_body["tokens"]["refresh_token"].as_str().unwrap();

        // Logout
        let logout_response = server
            .get("/auth/logout")
            .add_header(header::AUTHORIZATION, format!("Bearer {}", access_token))
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
        let context = create_test_context().await;
        let app = backend(&context);
        let server = TestServer::new(app).unwrap();

        // Login to get access token
        let login_response = server
            .post("/auth/login")
            .json(&json!({
                "username": "testuser",
                "password": "testpass123"
            }))
            .await;

        let login_body: Value = login_response.json();
        let access_token = login_body["tokens"]["access_token"].as_str().unwrap();

        // Access protected route
        let api_response = server
            .get("/api")
            .add_header(header::AUTHORIZATION, format!("Bearer {}", access_token))
            .await;

        api_response.assert_status(StatusCode::OK);
    }

    #[tokio::test]
    async fn test_protected_route_without_token() {
        let context = create_test_context().await;
        let app = backend(&context);
        let server = TestServer::new(app).unwrap();

        let response = server.get("/api").await;
        response.assert_status(StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_protected_route_with_invalid_token() {
        let context = create_test_context().await;
        let app = backend(&context);
        let server = TestServer::new(app).unwrap();

        let response = server
            .get("/api")
            .add_header(header::AUTHORIZATION, "Bearer invalid_token")
            .await;

        response.assert_status(StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_token_expiry() {
        let temp_db = NamedTempFile::new().unwrap();
        let database_url = format!("sqlite:{}", temp_db.path().to_str().unwrap());

        // Create config with very short token expiry
        let config = AppConfig {
            jwt: JwtConfig {
                secret: "test_secret_key_for_testing_only".to_string(),
                access_token_expiry: 1, // 1 second
                refresh_token_expiry: 86400,
            },
            database: DatabaseConfig {
                url: database_url.clone(),
            },
            ..Default::default()
        };

        let pool = SqlitePool::connect(&database_url).await.unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        let store = Store::new(pool);

        // Create test data
        let tenant = NewTenant {
            name: "Test Tenant".to_string(),
            description: Some("Test tenant".to_string()),
        };
        let tenant_id = store.create_tenant(tenant).await.unwrap();

        let password_hash = crate::routes::auth::hash_password("testpass123").unwrap();
        let user = NewUser {
            username: "testuser".to_string(),
            password_hash: Some(password_hash),
            email: Some("test@example.com".to_string()),
            tenant_id: Some(tenant_id),
            sso_provider: None,
            sso_id: None,
        };
        store.create_user(user).await.unwrap();

        let context = AppContext::new(config, store);
        let app = backend(&context);
        let server = TestServer::new(app).unwrap();

        // Login
        let login_response = server
            .post("/auth/login")
            .json(&json!({
                "username": "testuser",
                "password": "testpass123"
            }))
            .await;

        let login_body: Value = login_response.json();
        let access_token = login_body["tokens"]["access_token"].as_str().unwrap();

        // Wait for token to expire
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        // Try to use expired token
        let response = server
            .get("/api")
            .add_header(header::AUTHORIZATION, format!("Bearer {}", access_token))
            .await;

        response.assert_status(StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_malformed_json_login() {
        let context = create_test_context().await;
        let app = backend(&context);
        let server = TestServer::new(app).unwrap();

        let response = server
            .post("/auth/login")
            .text("not json")
            .await;

        response.assert_status(StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_missing_fields_login() {
        let context = create_test_context().await;
        let app = backend(&context);
        let server = TestServer::new(app).unwrap();

        let response = server
            .post("/auth/login")
            .json(&json!({
                "username": "testuser"
                // missing password
            }))
            .await;

        response.assert_status(StatusCode::BAD_REQUEST);
    }
}