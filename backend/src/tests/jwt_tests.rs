use axum::http;
use axum::body::Body;
use axum::http::{HeaderValue, Request};


use crate::auth::*;
use crate::cfg;

fn create_test_context() -> JwtContext {
    let settings = cfg::JwtSettings {
        access_token_expiry_minutes: 60,
        refresh_token_expiry_days: 1,
    };
    // For tests, create a JwtContext with a fixed secret
    let secret = "test_secret_key_for_jwt_testing";
    JwtContext::new(&settings, secret).unwrap()
}

#[test]
fn test_generate_access_token_success() {
    let ctx = create_test_context();
    let user_id = 123;
    let username = "test_user";
    let tenant_id = Some(456);

    let token = generate_access_token(&ctx, user_id, username, tenant_id).unwrap();

    // Token should be non-empty and contain JWT structure (header.payload.signature)
    let parts = token.split('.');
    assert_eq!(parts.count(), 3);
}

#[test]
fn test_generate_refresh_token_success() {
    let ctx = create_test_context();
    let user_id = 123;

    let token = generate_refresh_token(&ctx, user_id).unwrap();

    // Token should be non-empty and contain JWT structure
    let parts = token.split('.');
    assert_eq!(parts.count(), 3);
}

#[test]
fn test_decode_access_token_success() {
    let ctx = create_test_context();
    let user_id = 123;
    let username = "test_user";
    let tenant_id = Some(456);

    let token = generate_access_token(&ctx, user_id, username, tenant_id).unwrap();
    let claims = decode_access_token(&ctx, &token).unwrap();

    assert_eq!(claims.sub, user_id.to_string());
    assert_eq!(claims.username, username);
    assert_eq!(claims.tenant_id, tenant_id);
    assert_eq!(claims.token_type, TokenType::Access);
    assert!(claims.exp > claims.iat);
    assert!(!claims.jti.is_empty());
}

#[test]
fn test_decode_refresh_token_success() {
    let ctx = create_test_context();
    let user_id = 123;

    let token = generate_refresh_token(&ctx, user_id).unwrap();
    let claims = decode_refresh_token(&ctx, &token).unwrap();

    assert_eq!(claims.sub, user_id.to_string());
    assert_eq!(claims.token_type, TokenType::Refresh);
    assert!(claims.exp > claims.iat);
    assert!(!claims.jti.is_empty());
}

#[test]
fn test_decode_access_token_wrong_secret() {
    // Create a context with a different secret
    let settings = cfg::JwtSettings {
        access_token_expiry_minutes: 60,
        refresh_token_expiry_days: 1,
    };
    let wrong_secret = "wrong_secret_for_testing_1234567890";
    let wrong_ctx = JwtContext::new(&settings, wrong_secret).unwrap();
    let ctx = create_test_context();

    let user_id = 123;
    let username = "test_user";
    let token = generate_access_token(&ctx, user_id, username, None).unwrap();
    let result = decode_access_token(&wrong_ctx, &token);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), JwtError::DecodingFailed(_)));
}

#[test]
fn test_decode_invalid_token() {
    let ctx = create_test_context();
    let invalid_token = "invalid.token.format";

    let result = decode_access_token(&ctx, invalid_token);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), JwtError::DecodingFailed(_)));
}

#[test]
fn test_decode_malformed_token() {
    let ctx = create_test_context();
    let malformed_token = "not_a_jwt_token";

    let result = decode_access_token(&ctx, malformed_token);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), JwtError::InvalidToken));
}

#[test]
fn test_token_expiry() {
    use chrono::Utc;
    use jsonwebtoken as jwt;
    use uuid::Uuid;

    let ctx = create_test_context();
    let user_id = 123;
    let username = "test_user";

    // Create an expired token by manually setting past timestamps
    let now = Utc::now().timestamp();
    let expired_time = now - 3600; // 1 hour ago

    let header = jwt::Header::new(jwt::Algorithm::HS256);
    let expired_claims = AccessTokenClaims {
        sub: user_id.to_string(),
        username: username.to_string(),
        tenant_id: None,
        exp: expired_time, // Expired timestamp
        iat: expired_time - 3600, // Issued 2 hours ago
        jti: Uuid::new_v4().to_string(),
        token_type: TokenType::Access,
    };

    let expired_token = jwt::encode(&header, &expired_claims, &ctx.encoding_key).unwrap();

    // Test that expired token is rejected
    let result = decode_access_token(&ctx, &expired_token);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), JwtError::TokenExpired));

    // Test that a valid token still works
    let valid_token = generate_access_token(&ctx, user_id, username, None).unwrap();
    let claims = decode_access_token(&ctx, &valid_token).unwrap();
    assert_eq!(claims.sub, user_id.to_string());
    assert_eq!(claims.username, username);
}

#[test]
fn test_refresh_token_expiry() {
    use chrono::Utc;
    use jsonwebtoken as jwt;
    use uuid::Uuid;

    let ctx = create_test_context();
    let user_id = 123;

    // Create an expired refresh token by manually setting past timestamps
    let now = Utc::now().timestamp();
    let expired_time = now - 3600; // 1 hour ago

    let header = jwt::Header::new(jwt::Algorithm::HS256);
    let expired_refresh_claims = RefreshTokenClaims {
        sub: user_id.to_string(),
        exp: expired_time, // Expired timestamp
        iat: expired_time - 3600, // Issued 2 hours ago
        jti: Uuid::new_v4().to_string(),
        token_type: TokenType::Refresh,
    };

    let expired_refresh_token = jwt::encode(&header, &expired_refresh_claims, &ctx.encoding_key).unwrap();

    // Test that expired refresh token is rejected
    let result = decode_refresh_token(&ctx, &expired_refresh_token);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), JwtError::TokenExpired));

    // Test that a valid refresh token still works
    let valid_token = generate_refresh_token(&ctx, user_id).unwrap();
    let claims = decode_refresh_token(&ctx, &valid_token).unwrap();
    assert_eq!(claims.sub, user_id.to_string());
}

#[test]
fn test_future_token_valid() {
    use chrono::Utc;
    use jsonwebtoken as jwt;
    use uuid::Uuid;

    let ctx = create_test_context();
    let user_id = 123;
    let username = "test_user";

    // Create a token that expires far in the future
    let now = Utc::now().timestamp();
    let future_expiry = now + 86400; // 24 hours from now

    let header = jwt::Header::new(jwt::Algorithm::HS256);
    let future_claims = AccessTokenClaims {
        sub: user_id.to_string(),
        username: username.to_string(),
        tenant_id: None,
        exp: future_expiry,
        iat: now,
        jti: Uuid::new_v4().to_string(),
        token_type: TokenType::Access,
    };

    let future_token = jwt::encode(&header, &future_claims, &ctx.encoding_key).unwrap();

    // Test that future token is accepted
    let claims = decode_access_token(&ctx, &future_token).unwrap();
    assert_eq!(claims.sub, user_id.to_string());
    assert_eq!(claims.username, username);
    assert_eq!(claims.exp, future_expiry);
}

#[test]
fn test_access_token_used_as_refresh_token() {
    let ctx = create_test_context();
    let user_id = 123;
    let username = "test_user";

    let access_token = generate_access_token(&ctx, user_id, username, None).unwrap();

    // Try to decode access token as refresh token - should fail
    let result = decode_refresh_token(&ctx, &access_token);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), JwtError::InvalidToken));
}

#[test]
fn test_refresh_token_used_as_access_token() {
    let ctx = create_test_context();
    let user_id = 123;

    let refresh_token = generate_refresh_token(&ctx, user_id).unwrap();

    // Try to decode refresh token as access token - should fail
    let result = decode_access_token(&ctx, &refresh_token);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), JwtError::InvalidToken));
}

#[test]
fn test_decode_access_token_from_req_success() {
    let ctx = create_test_context();
    let user_id = 123;
    let username = "test_user";

    let token = generate_access_token(&ctx, user_id, username, None).unwrap();

    let mut req = Request::new(Body::empty());
    req.headers_mut().insert(
        http::header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
    );

    let claims = decode_access_token_from_req(&ctx, &req).unwrap();
    assert_eq!(claims.sub, user_id.to_string());
    assert_eq!(claims.username, username);
}

#[test]
fn test_decode_access_token_from_req_missing_header() {
    let ctx = create_test_context();
    let req = Request::new(Body::empty());

    let result = decode_access_token_from_req(&ctx, &req);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), JwtError::InvalidAuthorizationHeader));
}

#[test]
fn test_decode_access_token_from_req_wrong_format() {
    let ctx = create_test_context();
    let mut req = Request::new(Body::empty());

    // Missing "Bearer " prefix
    req.headers_mut().insert(
        http::header::AUTHORIZATION,
        HeaderValue::from_str("some_token").unwrap(),
    );

    let result = decode_access_token_from_req(&ctx, &req);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), JwtError::InvalidAuthorizationHeader));
}

#[test]
fn test_token_response_creation() {
    let ctx = create_test_context();
    let access_token = "access_token_string".to_string();
    let refresh_token = "refresh_token_string".to_string();

    let response = TokenResponse::new(&ctx, access_token.clone(), refresh_token.clone());

    assert_eq!(response.access_token, access_token);
    assert_eq!(response.refresh_token, refresh_token);
    assert_eq!(response.access_token_expires_in, ctx.access_token_expiry);
    assert_eq!(response.refresh_token_expires_in, ctx.refresh_token_expiry);
}

#[test]
fn test_different_tokens_have_different_jwt_ids() {
    let ctx = create_test_context();
    let user_id = 123;
    let username = "test_user";

    let token1 = generate_access_token(&ctx, user_id, username, None).unwrap();
    let token2 = generate_access_token(&ctx, user_id, username, None).unwrap();

    let claims1 = decode_access_token(&ctx, &token1).unwrap();
    let claims2 = decode_access_token(&ctx, &token2).unwrap();

    // JTIs should be different for different tokens
    assert_ne!(claims1.jti, claims2.jti);
}

#[test]
fn test_access_token_contains_correct_tenant_info() {
    let ctx = create_test_context();
    let user_id = 123;
    let username = "test_user";

    // Test with tenant
    let tenant_id = Some(456);
    let token_with_tenant = generate_access_token(&ctx, user_id, username, tenant_id).unwrap();
    let claims_with_tenant = decode_access_token(&ctx, &token_with_tenant).unwrap();
    assert_eq!(claims_with_tenant.tenant_id, tenant_id);

    // Test without tenant
    let token_without_tenant = generate_access_token(&ctx, user_id, username, None).unwrap();
    let claims_without_tenant = decode_access_token(&ctx, &token_without_tenant).unwrap();
    assert_eq!(claims_without_tenant.tenant_id, None);
}
