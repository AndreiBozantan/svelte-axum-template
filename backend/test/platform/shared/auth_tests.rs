use crate::platform::auth;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[test]
fn hash_password_creates_valid_hash() -> TestResult {
    let hash = auth::hash_password("test_password_123")?;
    assert!(hash.starts_with("$argon2id$"));
    assert!(hash.len() > 50);
    Ok(())
}

#[test]
fn hash_password_generates_different_hashes() -> TestResult {
    let hash1 = auth::hash_password("same_password")?;
    let hash2 = auth::hash_password("same_password")?;
    assert_ne!(hash1, hash2);
    Ok(())
}

#[test]
fn verify_password_success() -> TestResult {
    let hash = auth::hash_password("test_password")?;
    assert!(auth::verify_password("test_password", &hash)?);
    Ok(())
}

#[test]
fn verify_password_failure() -> TestResult {
    let hash = auth::hash_password("correct_password")?;
    assert!(!auth::verify_password("wrong_password", &hash)?);
    Ok(())
}

#[test]
fn verify_password_with_invalid_hash() {
    assert!(auth::verify_password("password", "not_a_valid_hash").is_err());
}

#[test]
fn hash_empty_password() -> TestResult {
    let hash = auth::hash_password("")?;
    assert!(auth::verify_password("", &hash)?);
    Ok(())
}

#[test]
fn hash_long_password() -> TestResult {
    let password = "a".repeat(1000);
    let hash = auth::hash_password(&password)?;
    assert!(auth::verify_password(&password, &hash)?);
    Ok(())
}

#[test]
fn hash_unicode_password() -> TestResult {
    let password = "🔐密码测试🔑";
    let hash = auth::hash_password(password)?;
    assert!(auth::verify_password(password, &hash)?);
    Ok(())
}
