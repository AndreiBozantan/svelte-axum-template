use crate::platform::crypto;

use crate::test::test_server::TestResult;

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
