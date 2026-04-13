use crate::auth::*;
use crate::cfg;

fn create_test_context() -> JwtContext {
    let settings = cfg::JwtSettings {
        access_token_expiry_minutes: 60,
        refresh_token_expiry_days: 1,
    };
    // for tests, create a JwtContext with a fixed secret
    let secret = "test_secret_key_for_jwt_testing";
    JwtContext::new(&settings, secret).unwrap()
}

#[test]
fn test_generate_access_token_success() {
    let ctx = create_test_context();
    let user_id = 123;
    let email = "test_user@example.com";
    let tenant_id = 456;

    let token = generate_token(&ctx, user_id, tenant_id, email, TokenType::Access, 1).unwrap();

    // token should be non-empty and contain JWT structure (header.payload.signature)
    let parts = token.value.split('.');
    assert_eq!(parts.count(), 3);
}

#[test]
fn test_generate_refresh_token_success() {
    let ctx = create_test_context();
    let user_id = 123;

    let refresh_token = generate_token(&ctx, user_id, 0, "test_user@example.com", TokenType::Refresh, 1).unwrap();

    // refresh token should be non-empty and contain JWT structure
    let parts = refresh_token.value.split('.');
    assert_eq!(parts.count(), 3);
}

#[test]
fn test_decode_access_token_success() {
    let ctx = create_test_context();
    let user_id = 123;
    let email = "test_user@example.com";
    let tenant_id = 456;

    let token = generate_token(&ctx, user_id, tenant_id, email, TokenType::Access, 1).unwrap();
    let claims = decode_token(&ctx, &token.value, TokenType::Access).unwrap();

    assert_eq!(claims.sub, user_id.to_string());
    assert_eq!(claims.email, email);
    assert_eq!(claims.tenant_id, tenant_id);
    assert_eq!(claims.token_type, TokenType::Access);
    assert!(claims.exp > claims.iat);
    assert!(!claims.jti.is_empty());
}

#[test]
fn test_decode_refresh_token_success() {
    let ctx = create_test_context();
    let user_id = 123;

    let token_with_claims = generate_token(&ctx, user_id, 0, "test_user@example.com", TokenType::Refresh, 1).unwrap();
    let claims = decode_token(&ctx, &token_with_claims.value, TokenType::Refresh).unwrap();

    assert_eq!(claims.sub, user_id.to_string());
    assert_eq!(claims.token_type, TokenType::Refresh);
    assert!(claims.exp > claims.iat);
    assert!(!claims.jti.is_empty());
}

#[test]
fn test_decode_access_token_wrong_secret() {
    // create a context with a different secret
    let settings = cfg::JwtSettings {
        access_token_expiry_minutes: 60,
        refresh_token_expiry_days: 1,
    };
    let wrong_secret = "wrong_secret_for_testing_1234567890";
    let wrong_ctx = JwtContext::new(&settings, wrong_secret).unwrap();
    let ctx = create_test_context();

    let user_id = 123;
    let email = "test_user@example.com";
    let token = generate_token(&ctx, user_id, 0, email, TokenType::Access, 1).unwrap();
    let result = decode_token(&wrong_ctx, &token.value, TokenType::Access);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), JwtError::DecodingFailed(_)));
}

#[test]
fn test_decode_invalid_token() {
    let ctx = create_test_context();
    let invalid_token = "invalid.token.format";

    let result = decode_token(&ctx, invalid_token, TokenType::Access);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), JwtError::DecodingFailed(_)));
}

#[test]
fn test_decode_malformed_token() {
    let ctx = create_test_context();
    let malformed_token = "not_a_jwt_token";

    let result = decode_token(&ctx, malformed_token, TokenType::Access);
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
    let email = "test_user@example.com";

    // create an expired token by manually setting past timestamps
    let now = Utc::now().timestamp();
    let expired_time = now - 3600; // 1 hour ago

    let header = jwt::Header::new(jwt::Algorithm::HS256);
    let expired_claims = TokenClaims {
        sub: user_id.to_string(),
        tenant_id: 0,
        email: email.to_string(),
        exp: expired_time,        // expired timestamp
        iat: expired_time - 3600, // issued 2 hours ago
        jti: Uuid::new_v4().to_string(),
        token_type: TokenType::Access,
    };

    let expired_token = jwt::encode(&header, &expired_claims, &ctx.encoding_key).unwrap();

    // test that expired token is rejected
    let result = decode_token(&ctx, &expired_token, TokenType::Access);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), JwtError::TokenExpired));

    // test that a valid token still works
    let valid_token = generate_token(&ctx, user_id, 0, email, TokenType::Access, 1).unwrap();
    let claims = decode_token(&ctx, &valid_token.value, TokenType::Access).unwrap();
    assert_eq!(claims.sub, user_id.to_string());
    assert_eq!(claims.email, email);
}

#[test]
fn test_refresh_token_expiry() {
    use chrono::Utc;
    use jsonwebtoken as jwt;
    use uuid::Uuid;

    let ctx = create_test_context();
    let user_id = 123;

    // create an expired refresh token by manually setting past timestamps
    let now = Utc::now().timestamp();
    let expired_time = now - 3600; // 1 hour ago

    let header = jwt::Header::new(jwt::Algorithm::HS256);
    let expired_refresh_claims = TokenClaims {
        sub: user_id.to_string(),
        tenant_id: 0,
        email: "test_user@example.com".to_string(),
        exp: expired_time,        // expired timestamp
        iat: expired_time - 3600, // issued 2 hours ago
        jti: Uuid::new_v4().to_string(),
        token_type: TokenType::Refresh,
    };

    let expired_refresh_token = jwt::encode(&header, &expired_refresh_claims, &ctx.encoding_key).unwrap();

    // test that expired refresh token is rejected
    let result = decode_token(&ctx, &expired_refresh_token, TokenType::Refresh);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), JwtError::TokenExpired));

    // test that a valid refresh token still works
    let valid_token = generate_token(&ctx, user_id, 0, "test_user@example.com", TokenType::Refresh, 1).unwrap();
    let claims = decode_token(&ctx, &valid_token.value, TokenType::Refresh).unwrap();
    assert_eq!(claims.sub, user_id.to_string());
}

#[test]
fn test_future_token_valid() {
    use chrono::Utc;
    use jsonwebtoken as jwt;
    use uuid::Uuid;

    let ctx = create_test_context();
    let user_id = 123;
    let email = "test_user@example.com";

    // create a token that expires far in the future
    let now = Utc::now().timestamp();
    let future_expiry = now + 86400; // 24 hours from now

    let header = jwt::Header::new(jwt::Algorithm::HS256);
    let future_claims = TokenClaims {
        sub: user_id.to_string(),
        tenant_id: 0,
        email: email.to_string(),
        exp: future_expiry,
        iat: now,
        jti: Uuid::new_v4().to_string(),
        token_type: TokenType::Access,
    };

    let future_token = jwt::encode(&header, &future_claims, &ctx.encoding_key).unwrap();

    // test that future token is accepted
    let claims = decode_token(&ctx, &future_token, TokenType::Access).unwrap();
    assert_eq!(claims.sub, user_id.to_string());
    assert_eq!(claims.email, email);
    assert_eq!(claims.exp, future_expiry);
}

#[test]
fn test_access_token_used_as_refresh_token() {
    let ctx = create_test_context();
    let user_id = 123;
    let email = "test_user@example.com";

    let access_token = generate_token(&ctx, user_id, 0, email, TokenType::Access, 1).unwrap();

    // try to decode access token as refresh token - should fail
    let result = decode_token(&ctx, &access_token.value, TokenType::Refresh);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), JwtError::InvalidToken));
}

#[test]
fn test_refresh_token_used_as_access_token() {
    let ctx = create_test_context();
    let user_id = 123;

    let refresh_token = generate_token(&ctx, user_id, 0, "test_user@example.com", TokenType::Refresh, 1).unwrap();

    // try to decode refresh token as access token - should fail
    let result = decode_token(&ctx, &refresh_token.value, TokenType::Access);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), JwtError::InvalidToken));
}

#[test]
fn test_different_tokens_have_different_jwt_ids() {
    let ctx = create_test_context();
    let user_id = 123;
    let email = "test_user@example.com";

    let token1 = generate_token(&ctx, user_id, 0, email, TokenType::Access, 1).unwrap();
    let token2 = generate_token(&ctx, user_id, 0, email, TokenType::Refresh, 1).unwrap();

    let claims1 = decode_token(&ctx, &token1.value, TokenType::Access).unwrap();
    let claims2 = decode_token(&ctx, &token2.value, TokenType::Refresh).unwrap();

    // JTIs should be different for different tokens
    assert_ne!(claims1.jti, claims2.jti);
}

#[test]
fn test_access_token_contains_correct_tenant_info() {
    let ctx = create_test_context();
    let user_id = 123;
    let email = "test_user@example.com";

    // test with tenant
    let tenant_id = 456;
    let token_with_tenant = generate_token(&ctx, user_id, tenant_id, email, TokenType::Access, 1).unwrap();
    let claims_with_tenant = decode_token(&ctx, &token_with_tenant.value, TokenType::Access).unwrap();
    assert_eq!(claims_with_tenant.tenant_id, tenant_id);

    // test without tenant
    let token_without_tenant = generate_token(&ctx, user_id, 0, email, TokenType::Access, 1).unwrap();
    let claims_without_tenant = decode_token(&ctx, &token_without_tenant.value, TokenType::Access).unwrap();
    assert_eq!(claims_without_tenant.tenant_id, 0);
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
