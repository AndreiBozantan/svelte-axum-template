use axum::body::Body;
use axum::http;
use axum::http::HeaderValue;
use axum::http::Request;

use crate::platform::config;
use crate::platform::cookies;
use crate::platform::crypto;
use crate::platform::jwt;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[test]
fn hash_password_creates_valid_hash() -> TestResult {
    let hash = crypto::hash_password("test_password_123")?;
    assert!(hash.starts_with("$argon2id$"));
    assert!(hash.len() > 50);
    Ok(())
}

#[test]
fn hash_password_generates_different_hashes() -> TestResult {
    let hash1 = crypto::hash_password("same_password")?;
    let hash2 = crypto::hash_password("same_password")?;
    assert_ne!(hash1, hash2);
    Ok(())
}

#[test]
fn verify_password_success() -> TestResult {
    let hash = crypto::hash_password("test_password")?;
    assert!(crypto::verify_password("test_password", &hash)?);
    Ok(())
}

#[test]
fn verify_password_failure() -> TestResult {
    let hash = crypto::hash_password("correct_password")?;
    assert!(!crypto::verify_password("wrong_password", &hash)?);
    Ok(())
}

#[test]
fn verify_password_with_invalid_hash() {
    assert!(crypto::verify_password("password", "not_a_valid_hash").is_err());
}

#[test]
fn hash_empty_password() -> TestResult {
    let hash = crypto::hash_password("")?;
    assert!(crypto::verify_password("", &hash)?);
    Ok(())
}

#[test]
fn hash_long_password() -> TestResult {
    let password = "a".repeat(1000);
    let hash = crypto::hash_password(&password)?;
    assert!(crypto::verify_password(&password, &hash)?);
    Ok(())
}

#[test]
fn hash_unicode_password() -> TestResult {
    let password = "🔐密码测试🔑";
    let hash = crypto::hash_password(password)?;
    assert!(crypto::verify_password(password, &hash)?);
    Ok(())
}

fn create_test_context() -> jwt::Context {
    let settings = config::JwtSettings {
        access_token_expiry_minutes: 60,
        refresh_token_expiry_days: 1,
    };
    let jwt_secret = "test__secret__key__for__jwt__testing";
    jwt::create_context(&settings, jwt_secret)
}

#[tokio::test]
async fn decode_access_token_from_req_cookie_success() -> TestResult {
    let context = create_test_context();
    let token = jwt::generate_token(&context, 123, 0, "test_user", jwt::TokenType::Access)?;
    let mut req = Request::new(Body::empty());
    req.headers_mut().insert(
        http::header::COOKIE,
        HeaderValue::from_str(&format!("access_token={}", token.value))?,
    );
    let claims = cookies::decode_token_from_req(&context, &req, jwt::TokenType::Access)?;
    assert_eq!(claims.sub, "123");
    assert_eq!(claims.email, "test_user");
    Ok(())
}

#[tokio::test]
async fn decode_access_token_from_req_success() -> TestResult {
    let context = create_test_context();
    let token = jwt::generate_token(&context, 123, 0, "test_user", jwt::TokenType::Access)?;
    let mut req = Request::new(Body::empty());
    req.headers_mut().insert(
        http::header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {}", token.value))?,
    );
    let claims = cookies::decode_token_from_req(&context, &req, jwt::TokenType::Access)?;
    assert_eq!(claims.sub, "123");
    assert_eq!(claims.email, "test_user");
    Ok(())
}

#[tokio::test]
async fn decode_access_token_from_req_missing_header() -> TestResult {
    let context = create_test_context();
    let req = Request::new(Body::empty());
    assert!(cookies::decode_token_from_req(&context, &req, jwt::TokenType::Access).is_err());
    Ok(())
}

#[tokio::test]
async fn decode_access_token_from_req_wrong_format() -> TestResult {
    let context = create_test_context();
    let mut req = Request::new(Body::empty());
    req.headers_mut()
        .insert(http::header::AUTHORIZATION, HeaderValue::from_str("some_token")?);
    assert!(cookies::decode_token_from_req(&context, &req, jwt::TokenType::Access).is_err());
    Ok(())
}
