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
    let server = create_test_server().await?;
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

#[tokio::test]
async fn revoke_token_success() -> TestResult {
    let server = create_test_server().await?;
    let (_body, _access_token, refresh_token) = login_testuser_and_get_tokens(&server).await?;
    let refresh_response = server
        .post("/api/auth/refresh")
        .add_cookie(cookie::Cookie::new("__Secure-refresh_token", refresh_token.clone()))
        .await;
    refresh_response.assert_status(StatusCode::OK);

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
    assert_eq!(r["details"]["password"][0], "password must be at least 8 characters");
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
    use crate::platform::identity::users::TRepository;
    use argon2::password_hash::{PasswordHasher, SaltString};
    use axum::http::StatusCode;
    use serde_json::json;

    // 1. manually instantiate the context and router so we retain access to  `ctx.db`
    let (ctx, server) = create_test_context_and_server().await?;
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
        .update_password_hash(&ctx.db, user_record.user.id, &outdated_hash)
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
