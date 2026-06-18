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

#[test]
fn needs_rehash_checks_correctly() -> TestResult {
    use argon2::password_hash::{PasswordHasher, SaltString};

    let hash_current = crypto::hash_password("my_password")?;
    assert!(!crypto::needs_rehash(&hash_current)?);

    // hash with outdated params (m_cost = 9999, t_cost = 1, p_cost = 1)
    let salt = SaltString::generate(argon2::password_hash::rand_core::OsRng);
    let outdated_params = argon2::Params::new(9999, 1, 1, None)?;
    let hasher = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, outdated_params);
    let hash_outdated = hasher.hash_password(b"my_password", &salt)?.to_string();

    assert!(crypto::needs_rehash(&hash_outdated)?);
    Ok(())
}

#[test]
fn test_constant_time_eq() {
    assert!(crypto::constant_time_eq("", ""));
    assert!(crypto::constant_time_eq("hello", "hello"));
    assert!(!crypto::constant_time_eq("hello", "world"));
    assert!(!crypto::constant_time_eq("hello", "hello0"));
    assert!(!crypto::constant_time_eq("hello0", "hello"));
}
