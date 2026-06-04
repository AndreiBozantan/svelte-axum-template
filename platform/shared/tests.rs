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

#[test]
fn generate_access_token_success() -> anyhow::Result<()> {
    let ctx = test_context()?;
    let token = jwt::generate_token(&ctx, 123, 456, "test_user@example.com", jwt::TokenType::Access, 1)?;
    assert_eq!(token.value.split('.').count(), 3);
    Ok(())
}

#[test]
fn generate_refresh_token_success() -> anyhow::Result<()> {
    let ctx = test_context()?;
    let token = jwt::generate_token(&ctx, 123, 0, "test_user@example.com", jwt::TokenType::Refresh, 1)?;
    assert_eq!(token.value.split('.').count(), 3);
    Ok(())
}

#[test]
fn decode_access_token_success() -> anyhow::Result<()> {
    let ctx = test_context()?;
    let token = jwt::generate_token(&ctx, 123, 456, "test_user@example.com", jwt::TokenType::Access, 1)?;
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
    let token = jwt::generate_token(&ctx, 123, 0, "test_user@example.com", jwt::TokenType::Refresh, 1)?;
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
    let token = jwt::generate_token(&ctx, 123, 0, "test@example.com", jwt::TokenType::Access, 1)?;
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
        Err(JwtError::InvalidToken) | Err(JwtError::DecodingFailed(_))
    ));
    Ok(())
}

#[test]
fn token_expiry() -> anyhow::Result<()> {
    let ctx = test_context()?;
    // Must exceed validation leeway (5s) so decode fails as expired.
    let token = jwt::generate_token(&ctx, 123, 0, "test@example.com", jwt::TokenType::Access, -60)?;
    let result = jwt::decode_token(&ctx, &token.value, jwt::TokenType::Access);
    assert!(matches!(result, Err(JwtError::TokenExpired)));
    Ok(())
}

#[test]
fn refresh_token_expiry() -> anyhow::Result<()> {
    let ctx = test_context()?;
    let token = jwt::generate_token(&ctx, 123, 0, "test@example.com", jwt::TokenType::Refresh, -60)?;
    let result = jwt::decode_token(&ctx, &token.value, jwt::TokenType::Refresh);
    assert!(matches!(result, Err(JwtError::TokenExpired)));
    Ok(())
}
