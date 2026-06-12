use axum::body::Body;
use axum::http;
use axum::http::HeaderValue;
use axum::http::Request;

use crate::platform::config;
use crate::platform::jwt;

use crate::platform::identity::tokens::utils;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn create_test_context() -> TestResult<jwt::Context> {
    let settings = config::JwtSettings {
        access_token_expiry_minutes: 60,
        refresh_token_expiry_days: 1,
    };
    let jwt_secret = "test__secret__key__for__jwt__testing";
    Ok(jwt::create_context(&settings, jwt_secret))
}

#[tokio::test]
async fn decode_access_token_from_req_cookie_success() -> TestResult {
    let context = create_test_context()?;
    let token = jwt::generate_token(&context, 123, 0, "test_user", jwt::TokenType::Access)?;
    let mut req = Request::new(Body::empty());
    req.headers_mut().insert(
        http::header::COOKIE,
        HeaderValue::from_str(&format!("access_token={}", token.value))?,
    );
    let claims = utils::decode_token_from_req(&context, &req, jwt::TokenType::Access)?;
    assert_eq!(claims.sub, "123");
    assert_eq!(claims.email, "test_user");
    Ok(())
}

#[tokio::test]
async fn decode_access_token_from_req_success() -> TestResult {
    let context = create_test_context()?;
    let token = jwt::generate_token(&context, 123, 0, "test_user", jwt::TokenType::Access)?;
    let mut req = Request::new(Body::empty());
    req.headers_mut().insert(
        http::header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {}", token.value))?,
    );
    let claims = utils::decode_token_from_req(&context, &req, jwt::TokenType::Access)?;
    assert_eq!(claims.sub, "123");
    assert_eq!(claims.email, "test_user");
    Ok(())
}

#[tokio::test]
async fn decode_access_token_from_req_missing_header() -> TestResult {
    let context = create_test_context()?;
    let req = Request::new(Body::empty());
    assert!(utils::decode_token_from_req(&context, &req, jwt::TokenType::Access).is_err());
    Ok(())
}

#[tokio::test]
async fn decode_access_token_from_req_wrong_format() -> TestResult {
    let context = create_test_context()?;
    let mut req = Request::new(Body::empty());
    req.headers_mut()
        .insert(http::header::AUTHORIZATION, HeaderValue::from_str("some_token")?);
    assert!(utils::decode_token_from_req(&context, &req, jwt::TokenType::Access).is_err());
    Ok(())
}
