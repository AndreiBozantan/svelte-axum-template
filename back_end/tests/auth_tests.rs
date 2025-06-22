#[cfg(test)]
mod tests {
    use axum::http::header;
    use axum::http::StatusCode;
    use axum_test::TestServer;
    use serde_json::json;
    use serde_json::Value;
    use tempfile::NamedTempFile;
    use tokio;

    use svelte_axum_template::*;

    const TEST_PASSWORD: &str = "abcdefghijklmnopqrstuvwxyz";
    const TEST_USERNAME: &str = "test_user";

    async fn create_test_server(config: Option<app::Config>) -> TestServer {
        let mut config = config.or(Some(app::Config {
            jwt: app::JwtConfig {
                secret: "test_secret_key_for_testing_only".to_string(),
                access_token_expiry: 3600,
                refresh_token_expiry: 86400,
            },
            ..Default::default()
        })).unwrap();

        // Create a temporary SQLite database file and use it for testing
        // TODO: try to remove the file after tests
        let temp_db = NamedTempFile::new().unwrap();
        config.database = app::DatabaseConfig {
            url: format!("sqlite:{}", temp_db.path().to_str().unwrap()),
            max_connections: 5,
        };

        let context = app::Context::new(config).await.unwrap();
        sqlx::migrate!("./migrations").run(&context.store.db_pool).await.unwrap();

        // Create test user
        let password_hash = auth::hash_password(TEST_PASSWORD).unwrap();
        let user = db::schema::NewUser {
            username: TEST_USERNAME.to_string(),
            password_hash: Some(password_hash),
            email: Some("test@example.com".to_string()),
            tenant_id: Some(1),
            sso_provider: None,
            sso_id: None,
        };
        context.store.create_user(user).await.unwrap();

        let router = routes::create_router(context);
        TestServer::new(router).unwrap()
    }

    #[tokio::test]
    async fn test_login_success() {
        let server = create_test_server(None).await;

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
        let server = create_test_server(None).await;

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
        let server = create_test_server(None).await;

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
        let server = create_test_server(None).await;

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
        let server = create_test_server(None).await;

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
        let server = create_test_server(None).await;

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
        let server = create_test_server(None).await;

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
        let server = create_test_server(None).await;

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
            .add_header(header::AUTHORIZATION, format!("Bearer {}", access_token))
            .await;

        api_response.assert_status(StatusCode::OK);
    }

    #[tokio::test]
    async fn test_protected_route_without_token() {
        let server = create_test_server(None).await;

        let response = server.get("/api").await;
        response.assert_status(StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_protected_route_with_invalid_token() {
        let server = create_test_server(None).await;

        let response = server
            .get("/api")
            .add_header(header::AUTHORIZATION, "Bearer invalid_token")
            .await;

        response.assert_status(StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_access_token_expiry() {
        // Create config with very short token expiry
        let config = app::Config {
            jwt: app::JwtConfig {
                secret: "test_secret_key_for_testing_only".to_string(),
                access_token_expiry: 1, // 1 second
                refresh_token_expiry: 86400,
            },
            ..Default::default()
        };

        let server = create_test_server(Some(config)).await;

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
        let server = create_test_server(None).await;

        let response = server
            .post("/auth/login")
            .text("not json")
            .await;

        response.assert_status(StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_missing_fields_login() {
        let server = create_test_server(None).await;

        let response = server
            .post("/auth/login")
            .json(&json!({
                "username": TEST_USERNAME
                // missing password
            }))
            .await;

        response.assert_status(StatusCode::BAD_REQUEST);
    }
}