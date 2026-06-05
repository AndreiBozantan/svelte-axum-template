use crate::config;
use crate::jwt;
use crate::jwt::JwtContext;
use crate::jwt::JwtError;

fn test_context() -> anyhow::Result<JwtContext> {
    let settings = config::JwtSettings {
        access_token_expiry_minutes: 60,
        refresh_token_expiry_days: 1,
    };
    let secret = "test_secret_key_for_jwt_testing";
    Ok(JwtContext::new(&settings, secret)?)
}

fn generate_expired_token(
    ctx: &JwtContext,
    user_id: i64,
    tenant_id: i64,
    email: &str,
    token_type: jwt::TokenType,
) -> Result<String, JwtError> {
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
    let token = jsonwebtoken::encode(&header, &claims, &ctx.encoding_key).map_err(JwtError::EncodingFailed)?;
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
    let wrong_ctx = JwtContext::new(&settings, "wrong_secret_key_for_jwt_testing")?;
    let token = jwt::generate_token(&ctx, 123, 0, "test@example.com", jwt::TokenType::Access)?;
    let result = jwt::decode_token(&wrong_ctx, &token.value, jwt::TokenType::Access);
    assert!(matches!(result, Err(JwtError::DecodingFailed(_))));
    Ok(())
}

#[test]
fn decode_malformed_token() -> anyhow::Result<()> {
    let ctx = test_context()?;
    let result = jwt::decode_token(&ctx, "not.a.valid.jwt.token", jwt::TokenType::Access);
    assert!(matches!(result, Err(JwtError::DecodingFailed(_))));
    Ok(())
}

#[test]
fn decode_invalid_token() -> anyhow::Result<()> {
    let ctx = test_context()?;
    let result = jwt::decode_token(&ctx, "invalid.token.here", jwt::TokenType::Access);
    assert!(matches!(
        result,
        Err(JwtError::InvalidToken | JwtError::DecodingFailed(_))
    ));
    Ok(())
}

#[test]
fn token_expiry() -> anyhow::Result<()> {
    let ctx = test_context()?;
    let token_value = generate_expired_token(&ctx, 123, 0, "test@example.com", jwt::TokenType::Access)?;
    let result = jwt::decode_token(&ctx, &token_value, jwt::TokenType::Access);
    assert!(matches!(result, Err(JwtError::TokenExpired)));
    Ok(())
}

#[test]
fn refresh_token_expiry() -> anyhow::Result<()> {
    let ctx = test_context()?;
    let token_value = generate_expired_token(&ctx, 123, 0, "test@example.com", jwt::TokenType::Refresh)?;
    let result = jwt::decode_token(&ctx, &token_value, jwt::TokenType::Refresh);
    assert!(matches!(result, Err(JwtError::TokenExpired)));
    Ok(())
}
