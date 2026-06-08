use argon2::Argon2;
use argon2::PasswordHasher;
use argon2::password_hash as ar2;

use crate::identity::auth;

#[test]
fn hash_password_creates_valid_hash() -> anyhow::Result<()> {
    let hash = auth::hash_password("test_password_123")?;
    assert!(hash.starts_with("$argon2id$"));
    assert!(hash.len() > 50);
    Ok(())
}

#[test]
fn hash_password_generates_different_hashes() -> anyhow::Result<()> {
    let hash1 = auth::hash_password("same_password")?;
    let hash2 = auth::hash_password("same_password")?;
    assert_ne!(hash1, hash2);
    Ok(())
}

#[test]
fn verify_password_success() -> anyhow::Result<()> {
    let hash = auth::hash_password("test_password")?;
    assert!(auth::verify_password("test_password", &hash)?);
    Ok(())
}

#[test]
fn verify_password_failure() -> anyhow::Result<()> {
    let hash = auth::hash_password("correct_password")?;
    assert!(!auth::verify_password("wrong_password", &hash)?);
    Ok(())
}

#[test]
fn verify_password_with_invalid_hash() {
    assert!(auth::verify_password("password", "not_a_valid_hash").is_err());
}

#[test]
fn hash_empty_password() -> anyhow::Result<()> {
    let hash = auth::hash_password("")?;
    assert!(auth::verify_password("", &hash)?);
    Ok(())
}

#[test]
fn dummy_hash_parameters_match_argon2_default() -> anyhow::Result<()> {
    let dummy = argon2::PasswordHash::new(auth::DUMMY_HASH)?;
    let salt = ar2::SaltString::generate(ar2::rand_core::OsRng);
    let reference = Argon2::default().hash_password(b"dummy-password-for-timing", &salt)?;
    assert_eq!(dummy.algorithm, reference.algorithm);
    Ok(())
}

#[test]
fn hash_long_password() -> anyhow::Result<()> {
    let password = "a".repeat(1000);
    let hash = auth::hash_password(&password)?;
    assert!(auth::verify_password(&password, &hash)?);
    Ok(())
}

#[test]
fn hash_unicode_password() -> anyhow::Result<()> {
    let password = "🔐密码测试🔑";
    let hash = auth::hash_password(password)?;
    assert!(auth::verify_password(password, &hash)?);
    Ok(())
}

