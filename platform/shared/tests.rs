use crate::config;
use crate::jwt;
use crate::jwt::Context;

fn test_context() -> anyhow::Result<Context> {
    let settings = config::JwtSettings {
        access_token_expiry_minutes: 60,
        refresh_token_expiry_days: 1,
    };
    let secret = "test_secret_key_for_jwt_testing";
    Ok(Context::new(&settings, secret)?)
}

fn generate_expired_token(
    ctx: &Context,
    user_id: i64,
    tenant_id: i64,
    email: &str,
    token_type: jwt::TokenType,
) -> Result<String, jwt::Error> {
    use chrono::Utc;
    use uuid::Uuid;

    let now = Utc::now().timestamp();
    let exp = now - 60; // 60s in the past (exceeds validation leeway of 5s)
    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    let claims = jwt::TokenClaims {
        sub: user_id.to_string(),
        tenant_id,
        email: email.to_string(),
        exp,
        iat: now - 3600,
        jti: Uuid::new_v4().to_string(),
        token_type,
    };
    let token = jsonwebtoken::encode(&header, &claims, &ctx.encoding_key).map_err(jwt::Error::EncodingFailed)?;
    Ok(token)
}

#[test]
fn generate_access_token_success() -> anyhow::Result<()> {
    let ctx = test_context()?;
    let token = jwt::generate_token(&ctx, 123, 456, "test_user@example.com", jwt::TokenType::Access)?;
    assert_eq!(token.value.split('.').count(), 3);
    Ok(())
}

#[test]
fn generate_refresh_token_success() -> anyhow::Result<()> {
    let ctx = test_context()?;
    let token = jwt::generate_token(&ctx, 123, 0, "test_user@example.com", jwt::TokenType::Refresh)?;
    assert_eq!(token.value.split('.').count(), 3);
    Ok(())
}

#[test]
fn decode_access_token_success() -> anyhow::Result<()> {
    let ctx = test_context()?;
    let token = jwt::generate_token(&ctx, 123, 456, "test_user@example.com", jwt::TokenType::Access)?;
    let claims = jwt::decode_token(&ctx, &token.value, jwt::TokenType::Access)?;
    assert_eq!(claims.sub, "123");
    assert_eq!(claims.email, "test_user@example.com");
    assert_eq!(claims.tenant_id, 456);
    assert_eq!(claims.token_type, jwt::TokenType::Access);
    Ok(())
}

#[test]
fn decode_refresh_token_success() -> anyhow::Result<()> {
    let ctx = test_context()?;
    let token = jwt::generate_token(&ctx, 123, 0, "test_user@example.com", jwt::TokenType::Refresh)?;
    let claims = jwt::decode_token(&ctx, &token.value, jwt::TokenType::Refresh)?;
    assert_eq!(claims.sub, "123");
    assert_eq!(claims.token_type, jwt::TokenType::Refresh);
    Ok(())
}

#[test]
fn decode_access_token_wrong_secret() -> anyhow::Result<()> {
    let ctx = test_context()?;
    let settings = config::JwtSettings {
        access_token_expiry_minutes: 60,
        refresh_token_expiry_days: 1,
    };
    let wrong_ctx = Context::new(&settings, "wrong_secret_key_for_jwt_testing")?;
    let token = jwt::generate_token(&ctx, 123, 0, "test@example.com", jwt::TokenType::Access)?;
    let result = jwt::decode_token(&wrong_ctx, &token.value, jwt::TokenType::Access);
    assert!(matches!(result, Err(jwt::Error::DecodingFailed(_))));
    Ok(())
}

#[test]
fn decode_malformed_token() -> anyhow::Result<()> {
    let ctx = test_context()?;
    let result = jwt::decode_token(&ctx, "not.a.valid.jwt.token", jwt::TokenType::Access);
    assert!(matches!(result, Err(jwt::Error::DecodingFailed(_))));
    Ok(())
}

#[test]
fn decode_invalid_token() -> anyhow::Result<()> {
    let ctx = test_context()?;
    let result = jwt::decode_token(&ctx, "invalid.token.here", jwt::TokenType::Access);
    assert!(matches!(
        result,
        Err(jwt::Error::InvalidToken | jwt::Error::DecodingFailed(_))
    ));
    Ok(())
}

#[test]
fn token_expiry() -> anyhow::Result<()> {
    let ctx = test_context()?;
    let token_value = generate_expired_token(&ctx, 123, 0, "test@example.com", jwt::TokenType::Access)?;
    let result = jwt::decode_token(&ctx, &token_value, jwt::TokenType::Access);
    assert!(matches!(result, Err(jwt::Error::ExpiredToken)));
    Ok(())
}

#[test]
fn refresh_token_expiry() -> anyhow::Result<()> {
    let ctx = test_context()?;
    let token_value = generate_expired_token(&ctx, 123, 0, "test@example.com", jwt::TokenType::Refresh)?;
    let result = jwt::decode_token(&ctx, &token_value, jwt::TokenType::Refresh);
    assert!(matches!(result, Err(jwt::Error::ExpiredToken)));
    Ok(())
}

#[test]
fn future_token_valid() -> anyhow::Result<()> {
    use chrono::Utc;
    use jsonwebtoken as jsonwt;
    use uuid::Uuid;

    let ctx = test_context()?;
    let user_id = 123;
    let email = "test_user@example.com";

    // create a token that expires far in the future
    let now = Utc::now().timestamp();
    let future_expiry = now + 86400; // 24 hours from now

    let header = jsonwt::Header::new(jsonwt::Algorithm::HS256);
    let future_claims = jwt::TokenClaims {
        sub: user_id.to_string(),
        tenant_id: 0,
        email: email.to_string(),
        exp: future_expiry,
        iat: now,
        jti: Uuid::new_v4().to_string(),
        token_type: jwt::TokenType::Access,
    };

    let future_token = jsonwt::encode(&header, &future_claims, &ctx.encoding_key)?;

    // test that future token is accepted
    let claims = jwt::decode_token(&ctx, &future_token, jwt::TokenType::Access)?;
    assert_eq!(claims.sub, user_id.to_string());
    assert_eq!(claims.email, email);
    assert_eq!(claims.exp, future_expiry);
    Ok(())
}

#[test]
fn access_token_used_as_refresh_token() -> anyhow::Result<()> {
    let ctx = test_context()?;
    let access_token = jwt::generate_token(&ctx, 123, 0, "test_user@example.com", jwt::TokenType::Access)?;

    // try to decode access token as refresh token - should fail
    let result = jwt::decode_token(&ctx, &access_token.value, jwt::TokenType::Refresh);
    assert!(result.is_err());
    assert!(matches!(result, Err(jwt::Error::InvalidToken)));
    Ok(())
}

#[test]
fn refresh_token_used_as_access_token() -> anyhow::Result<()> {
    let ctx = test_context()?;
    let refresh_token = jwt::generate_token(&ctx, 123, 0, "test_user@example.com", jwt::TokenType::Refresh)?;

    // try to decode refresh token as access token - should fail
    let result = jwt::decode_token(&ctx, &refresh_token.value, jwt::TokenType::Access);
    assert!(result.is_err());
    assert!(matches!(result, Err(jwt::Error::InvalidToken)));
    Ok(())
}

#[test]
fn different_tokens_have_different_jwt_ids() -> anyhow::Result<()> {
    let ctx = test_context()?;
    let email = "test_user@example.com";

    let token1 = jwt::generate_token(&ctx, 123, 0, email, jwt::TokenType::Access)?;
    let token2 = jwt::generate_token(&ctx, 123, 0, email, jwt::TokenType::Refresh)?;

    let claims1 = jwt::decode_token(&ctx, &token1.value, jwt::TokenType::Access)?;
    let claims2 = jwt::decode_token(&ctx, &token2.value, jwt::TokenType::Refresh)?;

    // JTIs should be different for different tokens
    assert_ne!(claims1.jti, claims2.jti);
    Ok(())
}

#[test]
fn access_token_contains_correct_tenant_info() -> anyhow::Result<()> {
    let ctx = test_context()?;
    let email = "test_user@example.com";

    // test with tenant
    let tenant_id = 456;
    let token_with_tenant = jwt::generate_token(&ctx, 123, tenant_id, email, jwt::TokenType::Access)?;
    let claims_with_tenant = jwt::decode_token(&ctx, &token_with_tenant.value, jwt::TokenType::Access)?;
    assert_eq!(claims_with_tenant.tenant_id, tenant_id);

    // test without tenant
    let token_without_tenant = jwt::generate_token(&ctx, 123, 0, email, jwt::TokenType::Access)?;
    let claims_without_tenant = jwt::decode_token(&ctx, &token_without_tenant.value, jwt::TokenType::Access)?;
    assert_eq!(claims_without_tenant.tenant_id, 0);
    Ok(())
}

