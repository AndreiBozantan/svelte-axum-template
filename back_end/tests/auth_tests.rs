#[cfg(test)]
mod tests {
    use axum::http::header;
    use axum::http::StatusCode;
    use axum_test::TestServer;
    use serde_json::json;
    use serde_json::Value;
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
        // Use in-memory database to avoid permission issues
        config.database = app::DatabaseConfig {
            url: "sqlite::memory:".to_string(),
            max_connections: 5,
            run_db_migrations_on_startup: true, // Enable auto-migrations for tests
        };

        let context = app::Context::new(config).await.unwrap();

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

        // Test token works before expiry
        let response_before = server
            .get("/api")
            .add_header(header::AUTHORIZATION, format!("Bearer {}", access_token))
            .await;
        response_before.assert_status(StatusCode::OK);

        // Wait for token to expire (longer wait to ensure expiration)
        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

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

        response.assert_status(StatusCode::UNSUPPORTED_MEDIA_TYPE);
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

        response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn test_auto_migrate_disabled() {
        // Test that when run_db_migrations_on_startup is disabled, we can still create a database connection
        // but need to handle the case where tables don't exist
        let config = app::Config {
            database: app::DatabaseConfig {
                url: "sqlite::memory:".to_string(),
                max_connections: 5,
                run_db_migrations_on_startup: false, // Disable auto-migrations
            },
            ..Default::default()
        };

        // This should succeed in creating the connection pool but won't run migrations
        let context = app::Context::new(config).await;
        assert!(context.is_ok(), "Context creation should succeed even with run_db_migrations_on_startup disabled");

        // However, trying to query user tables should fail because migrations weren't run
        let context = context.unwrap();
        let result = context.store.get_user_by_username("nonexistent").await;

        // This should fail because the user table doesn't exist (no migrations were run)
        assert!(result.is_err(), "Querying should fail when run_db_migrations_on_startup is disabled and no migrations have run");
    }
}