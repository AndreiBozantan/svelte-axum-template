use axum::http::StatusCode;
use serde_json::Value;
use serde_json::json;

use crate::platform::config;
use crate::platform::jwt;

use crate::test::test_server::*;

#[tokio::test]
async fn login_invalid_endpoint() -> TestResult {
    let server = create_test_server().await?;
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
async fn login_invalid_credentials() -> TestResult {
    let server = create_test_server().await?;
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
async fn login_nonexistent_user() -> TestResult {
    let server = create_test_server().await?;
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
async fn refresh_token_invalid() -> TestResult {
    let server = create_test_server().await?;
    let response = server.post("/api/auth/refresh").await;
    response.assert_status(StatusCode::UNAUTHORIZED);
    let body: Value = response.json();
    assert_eq!(body["code"], "invalid_token");
    Ok(())
}

#[tokio::test]
async fn login_success() -> TestResult {
    let server = create_test_server().await?;
    let (body, access_token, refresh_token) = login_testuser_and_get_tokens(&server).await?;
    assert!(!access_token.is_empty());
    assert!(!refresh_token.is_empty());
    assert_eq!(body["user"]["email"], TEST_USER_EMAIL);
    Ok(())
}

#[tokio::test]
async fn malformed_json_login() -> TestResult {
    let server = create_test_server().await?;
    let response = server.post("/api/auth/login").text("not json").await;
    response.assert_status(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    let r: Value = response.json();
    assert_eq!(r["code"], "validation_failed");
    assert!(r["details"]["body"][0].is_string());
    Ok(())
}

#[tokio::test]
async fn missing_fields_login() -> TestResult {
    let server = create_test_server().await?;
    let response = server
        .post("/api/auth/login")
        .json(&json!({ "email": TEST_USER_EMAIL }))
        .await;
    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);
    let r: Value = response.json();
    assert_eq!(r["code"], "validation_failed");
    assert!(r["details"]["body"][0].is_string());
    Ok(())
}

#[tokio::test]
async fn refresh_token_success() -> TestResult {
    let server = create_test_server().await?;
    let (_body, _access_token, refresh_token) = login_testuser_and_get_tokens(&server).await?;
    let refresh_response = server
        .post("/api/auth/refresh")
        .add_cookie(cookie::Cookie::new("__Secure-refresh_token", refresh_token.clone()))
        .await;
    refresh_response.assert_status(StatusCode::OK);
    let refresh_body: Value = refresh_response.json();
    assert!(!refresh_response.cookie("__Host-access_token").value().is_empty());
    assert_eq!(refresh_body["user"]["email"], TEST_USER_EMAIL);
    Ok(())
}

#[tokio::test]
async fn refresh_token_reuse_detection() -> TestResult {
    let (ctx, server) = create_auth_test_context_and_server().await?;

    // register the test user
    let register_resp = server
        .post("/api/auth/register")
        .json(&json!({
            "email": TEST_USER_EMAIL,
            "password": TEST_PASSWORD,
            "first_name": "Test",
            "last_name": "User"
        }))
        .await;
    register_resp.assert_status(StatusCode::CREATED);

    let (_body, _access_token, refresh_token_1) = login_testuser_and_get_tokens(&server).await?;

    // first refresh: rotates refresh_token_1 to refresh_token_2
    let refresh_response_1 = server
        .post("/api/auth/refresh")
        .add_cookie(cookie::Cookie::new("__Secure-refresh_token", refresh_token_1.clone()))
        .await;
    refresh_response_1.assert_status(StatusCode::OK);
    let refresh_token_2 = refresh_response_1.cookie("__Secure-refresh_token").value().to_string();
    assert!(!refresh_token_2.is_empty());
    assert_ne!(refresh_token_1, refresh_token_2);

    // decode refresh_token_1 to get JTI
    let claims = jwt::decode_token(&ctx.jwt, &refresh_token_1, jwt::TokenType::Refresh)?;

    // manually set revoked_at to 15 seconds ago to simulate being outside the grace period
    sqlx::query("UPDATE refresh_tokens SET revoked_at = datetime('now', '-15 seconds') WHERE jti = ?")
        .bind(&claims.jti)
        .execute(&ctx.db)
        .await?;

    // reuse refresh_token_1: should fail with UNAUTHORIZED
    let reuse_response = server
        .post("/api/auth/refresh")
        .add_cookie(cookie::Cookie::new("__Secure-refresh_token", refresh_token_1.clone()))
        .await;
    reuse_response.assert_status(StatusCode::UNAUTHORIZED);

    // because of reuse detection, all active tokens for the user should be revoked.
    // try refreshing with the new refresh_token_2: should now also fail with UNAUTHORIZED.
    let subsequent_refresh_response = server
        .post("/api/auth/refresh")
        .add_cookie(cookie::Cookie::new("__Secure-refresh_token", refresh_token_2))
        .await;
    subsequent_refresh_response.assert_status(StatusCode::UNAUTHORIZED);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refresh_token_concurrent_reuse_within_grace_period() -> TestResult {
    let server = create_test_server().await?;
    let (_body, _access_token, refresh_token) = login_testuser_and_get_tokens(&server).await?;

    let server_arc = std::sync::Arc::new(server);
    let token_arc = std::sync::Arc::new(refresh_token);

    let count = 15;
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(count));
    let mut handles = Vec::new();
    for _ in 0..count {
        let server_clone = server_arc.clone();
        let token_clone = token_arc.clone();
        let barrier_clone = barrier.clone();
        handles.push(tokio::spawn(async move {
            barrier_clone.wait().await;
            server_clone
                .post("/api/auth/refresh")
                .add_cookie(cookie::Cookie::new("__Secure-refresh_token", (*token_clone).clone()))
                .await
        }));
    }

    let mut ok_count = 0;
    for handle in handles {
        let res = handle.await?;
        if res.status_code() == StatusCode::OK {
            ok_count += 1;
        }
    }

    // With a 10-second grace period, all concurrent requests within the window should succeed.
    assert_eq!(
        ok_count, count,
        "Expected all {count} concurrent refresh requests within the grace period to succeed, but only {ok_count} succeeded."
    );

    Ok(())
}

#[tokio::test]
async fn refresh_token_reuse_outside_grace_period() -> TestResult {
    let (ctx, server) = create_auth_test_context_and_server().await?;

    // Register the test user
    let register_resp = server
        .post("/api/auth/register")
        .json(&json!({
            "email": TEST_USER_EMAIL,
            "password": TEST_PASSWORD,
            "first_name": "Test",
            "last_name": "User"
        }))
        .await;
    register_resp.assert_status(StatusCode::CREATED);

    let (_body, _access_token, refresh_token_1) = login_testuser_and_get_tokens(&server).await?;

    // 1. Perform a legitimate refresh to rotate refresh_token_1 to refresh_token_2
    let refresh_response_1 = server
        .post("/api/auth/refresh")
        .add_cookie(cookie::Cookie::new("__Secure-refresh_token", refresh_token_1.clone()))
        .await;
    refresh_response_1.assert_status(StatusCode::OK);
    let refresh_token_2 = refresh_response_1.cookie("__Secure-refresh_token").value().to_string();

    // 2. Decode refresh_token_1 to get its JTI so we can find it in the DB
    let claims = jwt::decode_token(&ctx.jwt, &refresh_token_1, jwt::TokenType::Refresh)?;

    // 3. Manually update the revoked_at field of refresh_token_1 in DB to be 15 seconds ago (outside 10s grace period)
    sqlx::query("UPDATE refresh_tokens SET revoked_at = datetime('now', '-15 seconds') WHERE jti = ?")
        .bind(&claims.jti)
        .execute(&ctx.db)
        .await?;

    // 4. Try to reuse refresh_token_1 (outside grace period) - should fail with UNAUTHORIZED
    let reuse_response = server
        .post("/api/auth/refresh")
        .add_cookie(cookie::Cookie::new("__Secure-refresh_token", refresh_token_1.clone()))
        .await;
    reuse_response.assert_status(StatusCode::UNAUTHORIZED);

    // 5. Because it was outside the grace period, breach detection should have revoked the new token_2 as well
    let subsequent_refresh_response = server
        .post("/api/auth/refresh")
        .add_cookie(cookie::Cookie::new("__Secure-refresh_token", refresh_token_2))
        .await;
    subsequent_refresh_response.assert_status(StatusCode::UNAUTHORIZED);

    Ok(())
}

#[tokio::test]
async fn revoke_token_success() -> TestResult {
    let (ctx, server) = create_auth_test_context_and_server().await?;

    // Register the test user
    let register_resp = server
        .post("/api/auth/register")
        .json(&json!({
            "email": TEST_USER_EMAIL,
            "password": TEST_PASSWORD,
            "first_name": "Test",
            "last_name": "User"
        }))
        .await;
    register_resp.assert_status(StatusCode::CREATED);

    let (_body, _access_token, refresh_token) = login_testuser_and_get_tokens(&server).await?;
    let refresh_response = server
        .post("/api/auth/refresh")
        .add_cookie(cookie::Cookie::new("__Secure-refresh_token", refresh_token.clone()))
        .await;
    refresh_response.assert_status(StatusCode::OK);

    // Decode refresh_token to get JTI
    let claims = jwt::decode_token(&ctx.jwt, &refresh_token, jwt::TokenType::Refresh)?;

    // Manually set revoked_at to 15 seconds ago to simulate being outside the grace period
    sqlx::query("UPDATE refresh_tokens SET revoked_at = datetime('now', '-15 seconds') WHERE jti = ?")
        .bind(&claims.jti)
        .execute(&ctx.db)
        .await?;

    let refresh_response = server
        .post("/api/auth/refresh")
        .add_cookie(cookie::Cookie::new("__Secure-refresh_token", refresh_token.clone()))
        .await;
    refresh_response.assert_status(StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn logout_success() -> TestResult {
    let server = create_test_server().await?;
    let (_body, _access_token, refresh_token) = login_testuser_and_get_tokens(&server).await?;
    let logout_response = server
        .post("/api/auth/logout")
        .add_cookie(cookie::Cookie::new("__Secure-refresh_token", refresh_token.clone()))
        .await;
    logout_response.assert_status(StatusCode::NO_CONTENT);

    let refresh_response = server
        .post("/api/auth/refresh")
        .add_cookie(cookie::Cookie::new("__Secure-refresh_token", refresh_token.clone()))
        .await;
    refresh_response.assert_status(StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn access_token_expiry() -> TestResult {
    use chrono::Utc;
    use uuid::Uuid;

    let server = create_test_server().await?;
    let login_response = server
        .post("/api/auth/login")
        .json(&json!({
            "email": TEST_USER_EMAIL,
            "password": TEST_PASSWORD
        }))
        .await;
    let valid_access_token = login_response.cookie("__Host-access_token").value().to_string();

    let response_valid = server
        .get("/api/users/me")
        .add_cookie(cookie::Cookie::new("__Host-access_token", valid_access_token.clone()))
        .await;
    response_valid.assert_status(StatusCode::OK);

    let jwt_settings = config::JwtSettings {
        access_token_expiry_minutes: 60,
        refresh_token_expiry_days: 1,
    };
    let jwt_secret = "test__secret__key__for__jwt__testing";
    let jwt_context = jwt::create_context(&jwt_settings, jwt_secret);

    let now = Utc::now().timestamp();
    let expired_time = now - 3600;
    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    let expired_claims = jwt::TokenClaims {
        sub: "1".to_string(),
        tenant_id: 0,
        email: TEST_USER_EMAIL.to_string(),
        exp: expired_time,
        iat: expired_time - 3600,
        jti: Uuid::new_v4().to_string(),
        token_type: jwt::TokenType::Access,
    };
    let expired_token = jsonwebtoken::encode(&header, &expired_claims, &jwt_context.encoding_key)?;

    let response_expired = server
        .get("/api/users/me")
        .add_cookie(cookie::Cookie::new("__Host-access_token", expired_token))
        .await;
    response_expired.assert_status(StatusCode::UNAUTHORIZED);
    let body: Value = response_expired.json();
    assert_eq!(body["code"], "expired_token");
    Ok(())
}

#[tokio::test]
async fn account_lockout_after_failed_attempts() -> TestResult {
    let server = create_test_server().await?;
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
async fn register_invalid_email() -> TestResult {
    let server = create_test_server().await?;
    let response = server
        .post("/api/auth/register")
        .json(&json!({
            "email": "not-an-email",
            "password": TEST_PASSWORD,
            "first_name": "Test",
            "last_name": "User"
        }))
        .await;
    response.assert_status(StatusCode::BAD_REQUEST);
    let r: Value = response.json();
    assert_eq!(r["code"], "validation_failed");
    assert_eq!(r["details"]["email"][0], "invalid email address");
    Ok(())
}

#[tokio::test]
async fn register_invalid_password() -> TestResult {
    let server = create_test_server().await?;
    let response = server
        .post("/api/auth/register")
        .json(&json!({
            "email": "valid_but_new@example.com",
            "password": "short",
            "first_name": "Test",
            "last_name": "User"
        }))
        .await;
    response.assert_status(StatusCode::BAD_REQUEST);
    let r: Value = response.json();
    assert_eq!(r["code"], "validation_failed");
    assert_eq!(
        r["details"]["password"][0],
        "password must be between 8 and 72 characters"
    );
    Ok(())
}

#[tokio::test]
async fn register_already_exists() -> TestResult {
    let server = create_test_server().await?;
    // Register once
    let response1 = server
        .post("/api/auth/register")
        .json(&json!({
            "email": "already_exists@example.com",
            "password": TEST_PASSWORD,
            "first_name": "Test",
            "last_name": "User"
        }))
        .await;
    response1.assert_status(StatusCode::CREATED);

    // Register again with the same email
    let response2 = server
        .post("/api/auth/register")
        .json(&json!({
            "email": "already_exists@example.com",
            "password": TEST_PASSWORD,
            "first_name": "Test",
            "last_name": "User"
        }))
        .await;
    response2.assert_status(StatusCode::CONFLICT);
    let r: Value = response2.json();
    assert_eq!(r["code"], "user_already_exists");
    Ok(())
}

#[tokio::test]
async fn refresh_token_not_in_db() -> TestResult {
    use chrono::Utc;
    use jsonwebtoken;
    use uuid::Uuid;

    let server = create_test_server().await?;

    // construct a JWT refresh token that is signed with our key, but its JTI does not exist in the database
    let jwt_settings = config::JwtSettings {
        access_token_expiry_minutes: 60,
        refresh_token_expiry_days: 1,
    };
    let jwt_secret = "test__secret__key__for__jwt__testing";
    let jwt_context = jwt::create_context(&jwt_settings, jwt_secret);

    let now = Utc::now().timestamp();
    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    let claims = jwt::TokenClaims {
        sub: "1".to_string(),
        tenant_id: 0,
        email: TEST_USER_EMAIL.to_string(),
        exp: now + 3600,
        iat: now,
        jti: Uuid::new_v4().to_string(), // JTI that won't exist in DB
        token_type: jwt::TokenType::Refresh,
    };
    let token = jsonwebtoken::encode(&header, &claims, &jwt_context.encoding_key)?;

    let response = server
        .post("/api/auth/refresh")
        .add_cookie(cookie::Cookie::new("__Secure-refresh_token", token))
        .await;
    response.assert_status(StatusCode::UNAUTHORIZED);
    let body: Value = response.json();
    assert_eq!(body["code"], "invalid_token");
    Ok(())
}

#[tokio::test]
async fn login_rehashes_outdated_password_hash_api() -> TestResult {
    use crate::platform::common;
    use crate::platform::crypto;
    use crate::platform::identity::users;
    use argon2::password_hash::{PasswordHasher, SaltString};
    use axum::http::StatusCode;
    use serde_json::json;

    // 1. manually instantiate the context and router so we retain access to  `ctx.db`
    let (ctx, server) = create_auth_test_context_and_server().await?;
    let email = common::Email::parse("api_rehash_test@example.com").ok_or("invalid email")?;

    // 2. register the user via HTTP
    let register_resp = server
        .post("/api/auth/register")
        .json(&json!({
            "email": email.as_str(),
            "password": "my_secure_password_123",
            "first_name": "Test",
            "last_name": "User"
        }))
        .await;
    register_resp.assert_status(StatusCode::CREATED);

    // 3. modify their password hash to be outdated in the database
    let salt = SaltString::generate(argon2::password_hash::rand_core::OsRng);
    let outdated_params = argon2::Params::new(9999, 1, 1, None)?;
    let hasher = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, outdated_params);
    let outdated_hash = hasher.hash_password(b"my_secure_password_123", &salt)?.to_string();

    let user_record = users::db::Repository
        .find_auth_details_by_email(&ctx.db, &email)
        .await?
        .ok_or("user record not found")?;

    users::db::Repository
        .update_password_hash(&ctx.db, user_record.user.tenant_id, user_record.user.id, &outdated_hash)
        .await?;

    // 4. log in over HTTP (this triggers the upgrade logic inside the service layer)
    let login_resp = server
        .post("/api/auth/login")
        .json(&json!({
            "email": email.as_str(),
            "password": "my_secure_password_123"
        }))
        .await;
    login_resp.assert_status(StatusCode::OK);

    // 5. verify the password hash has been upgraded in the database
    let auth_record_after = users::db::Repository
        .find_auth_details_by_email(&ctx.db, &email)
        .await?
        .ok_or("user record not found after login")?;
    let updated_hash = auth_record_after
        .password_hash
        .as_deref()
        .ok_or("password hash not found")?;
    assert_ne!(updated_hash, outdated_hash.as_str());
    assert!(!crypto::needs_rehash(updated_hash)?);

    Ok(())
}

#[tokio::test]
async fn refresh_token_tenant_isolation() -> TestResult {
    use crate::platform::common;
    use crate::platform::identity::tokens;
    use crate::platform::identity::users;

    let (ctx, _server) = create_auth_test_context_and_server().await?;

    // 1. Insert Tenant 2 into the database
    sqlx::query(
        "INSERT INTO tenants (id, created_at, updated_at, status, name) \
         VALUES (2, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'active', 'Tenant 2')",
    )
    .execute(&ctx.db)
    .await?;

    // 2. Create User 2 belonging to Tenant 2
    let email = common::Email::parse("tenant2@example.com").ok_or("invalid email")?;
    let user2 = users::db::Repository
        .create_user(
            &ctx.db,
            users::CreateUserCommand {
                tenant_id: common::TenantId(2),
                status: users::UserStatus::Active,
                email,
                first_name: Some("Tenant2".to_string()),
                middle_name: None,
                last_name: Some("User".to_string()),
                password_hash: None,
                sso_provider: None,
                sso_id: None,
            },
        )
        .await?;

    // 3. Verify that the database foreign key constraint prevents inserting a mismatched token
    let mismatched_token_cmd = tokens::CreateRefreshTokenCommand {
        jti: uuid::Uuid::new_v4().to_string(),
        tenant_id: common::TenantId(0), // default tenant
        user_id: user2.id,              // user belonging to Tenant 2
        token_hash: "dummy_hash".to_string(),
        expires_at: chrono::Utc::now().naive_utc(),
    };

    let insert_result = tokens::db::Repository.create(&ctx.db, mismatched_token_cmd).await;

    // The insert MUST fail due to foreign key constraint violation
    assert!(insert_result.is_err());
    let err_msg = match insert_result {
        Err(err) => err.to_string(),
        Ok(()) => return Err("expected insert to fail but it succeeded".into()),
    };
    assert!(err_msg.contains("FOREIGN KEY constraint failed"));

    // 4. Verify that users::db::Repository::find_by_id scopes by tenant_id correctly
    // If we look up user2.id under Tenant 0 (default tenant), it must fail with RowNotFound
    let user_lookup_result = users::db::Repository
        .find_by_id(&ctx.db, common::TenantId(0), user2.id)
        .await;

    assert!(matches!(
        user_lookup_result,
        Err(crate::platform::db::Error::RowNotFound)
    ));

    // Looking up user2.id under its correct Tenant 2 must succeed
    let user_lookup_success = users::db::Repository
        .find_by_id(&ctx.db, common::TenantId(2), user2.id)
        .await?;
    assert_eq!(user_lookup_success.id, user2.id);

    Ok(())
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn refresh_token_cleanup_task_deletes_expired() -> TestResult {
    use crate::platform::common;
    use crate::platform::identity::tokens;
    use crate::platform::identity::users;

    let (ctx, _server) = create_auth_test_context_and_server().await?;

    // create a user for testing
    let email = common::Email::parse("cleanup_test@example.com").ok_or("invalid email")?;
    let user = users::db::Repository
        .create_user(
            &ctx.db,
            users::CreateUserCommand {
                tenant_id: common::TenantId(0),
                status: users::UserStatus::Active,
                email,
                first_name: Some("Cleanup".to_string()),
                middle_name: None,
                last_name: Some("User".to_string()),
                password_hash: None,
                sso_provider: None,
                sso_id: None,
            },
        )
        .await?;

    // insert three tokens:
    // 1. One active (non-expired, non-revoked)
    // 2. One expired
    // 3. One revoked and expired
    // 4. One revoked but not expired

    let now = chrono::Utc::now().naive_utc();

    let active_jti = uuid::Uuid::new_v4().to_string();
    tokens::db::Repository
        .create(
            &ctx.db,
            tokens::CreateRefreshTokenCommand {
                jti: active_jti.clone(),
                tenant_id: common::TenantId(0),
                user_id: user.id,
                token_hash: "hash_active".to_string(),
                expires_at: now + chrono::Duration::hours(2),
            },
        )
        .await?;

    let expired_jti = uuid::Uuid::new_v4().to_string();
    tokens::db::Repository
        .create(
            &ctx.db,
            tokens::CreateRefreshTokenCommand {
                jti: expired_jti.clone(),
                tenant_id: common::TenantId(0),
                user_id: user.id,
                token_hash: "hash_expired".to_string(),
                expires_at: now - chrono::Duration::hours(2),
            },
        )
        .await?;

    let revoked_expired_jti = uuid::Uuid::new_v4().to_string();
    tokens::db::Repository
        .create(
            &ctx.db,
            tokens::CreateRefreshTokenCommand {
                jti: revoked_expired_jti.clone(),
                tenant_id: common::TenantId(0),
                user_id: user.id,
                token_hash: "hash_rev_exp".to_string(),
                expires_at: now - chrono::Duration::hours(1),
            },
        )
        .await?;
    tokens::db::Repository
        .revoke_by_jti(&ctx.db, common::TenantId(0), &revoked_expired_jti)
        .await?;

    let revoked_active_jti = uuid::Uuid::new_v4().to_string();
    tokens::db::Repository
        .create(
            &ctx.db,
            tokens::CreateRefreshTokenCommand {
                jti: revoked_active_jti.clone(),
                tenant_id: common::TenantId(0),
                user_id: user.id,
                token_hash: "hash_rev_act".to_string(),
                expires_at: now + chrono::Duration::hours(1),
            },
        )
        .await?;
    tokens::db::Repository
        .revoke_by_jti(&ctx.db, common::TenantId(0), &revoked_active_jti)
        .await?;

    // perform cleanup with current time
    let deleted_count = tokens::db::Repository.delete_expired(&ctx.db, now).await?;

    // we expect 2 tokens to have been deleted: the expired one and the revoked-and-expired one
    assert_eq!(deleted_count, 2);

    // verify active token still exists
    let active_token = tokens::db::Repository
        .find_by_jti(&ctx.db, common::TenantId(0), &active_jti)
        .await;
    assert!(active_token.is_ok());

    // verify revoked but active token still exists
    let revoked_active_token = tokens::db::Repository
        .find_by_jti(&ctx.db, common::TenantId(0), &revoked_active_jti)
        .await;
    assert!(revoked_active_token.is_ok());

    // verify expired token is gone
    let expired_token = tokens::db::Repository
        .find_by_jti(&ctx.db, common::TenantId(0), &expired_jti)
        .await;
    assert!(matches!(expired_token, Err(crate::platform::db::Error::RowNotFound)));

    // verify revoked and expired token is gone
    let revoked_expired_token = tokens::db::Repository
        .find_by_jti(&ctx.db, common::TenantId(0), &revoked_expired_jti)
        .await;
    assert!(matches!(
        revoked_expired_token,
        Err(crate::platform::db::Error::RowNotFound)
    ));

    Ok(())
}

#[tokio::test]
async fn test_begin_google_flow_adds_prompt() -> TestResult {
    let settings = crate::platform::config::AppSettings {
        oauth: crate::platform::config::OAuthSettings {
            google_client_id: "mock-client-id".to_string(),
            google_client_secret: "mock-client-secret".to_string(),
            google_redirect_uri: "http://localhost/callback".to_string(),
            ..Default::default()
        },
        // the default database url points at the on-disk dev database; tests must not touch it
        database: crate::platform::config::DatabaseSettings {
            url: "sqlite::memory:".to_string(),
            min_connections: 1,
            max_connections: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    let ctx = crate::platform::common::Context::create(settings, "test__secret__key__for__jwt__testing").await?;

    let auth_service = crate::platform::identity::auth::Service::new(
        crate::platform::identity::users::db::Repository,
        crate::platform::identity::tokens::db::Repository,
        ctx.clone(),
    );
    let oauth_service = crate::platform::identity::oauth::Service::new(ctx, auth_service);

    let (url, _state) = oauth_service.begin_google_flow(None)?;
    assert!(url.to_string().contains("prompt=select_account"));

    Ok(())
}
