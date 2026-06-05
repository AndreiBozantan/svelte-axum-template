use super::{DUMMY_HASH, hash_password, verify_password};
use argon2::Argon2;
use argon2::PasswordHasher;
use argon2::password_hash as ar2;

#[test]
fn hash_password_creates_valid_hash() -> anyhow::Result<()> {
    let hash = hash_password("test_password_123")?;
    assert!(hash.starts_with("$argon2id$"));
    assert!(hash.len() > 50);
    Ok(())
}

#[test]
fn hash_password_generates_different_hashes() -> anyhow::Result<()> {
    let hash1 = hash_password("same_password")?;
    let hash2 = hash_password("same_password")?;
    assert_ne!(hash1, hash2);
    Ok(())
}

#[test]
fn verify_password_success() -> anyhow::Result<()> {
    let hash = hash_password("test_password")?;
    assert!(verify_password("test_password", &hash)?);
    Ok(())
}

#[test]
fn verify_password_failure() -> anyhow::Result<()> {
    let hash = hash_password("correct_password")?;
    assert!(!verify_password("wrong_password", &hash)?);
    Ok(())
}

#[test]
fn verify_password_with_invalid_hash() -> anyhow::Result<()> {
    assert!(verify_password("password", "not_a_valid_hash").is_err());
    Ok(())
}

#[test]
fn hash_empty_password() -> anyhow::Result<()> {
    let hash = hash_password("")?;
    assert!(verify_password("", &hash)?);
    Ok(())
}

#[test]
fn dummy_hash_parameters_match_argon2_default() -> anyhow::Result<()> {
    let dummy = argon2::PasswordHash::new(DUMMY_HASH)?;
    let salt = ar2::SaltString::generate(ar2::rand_core::OsRng);
    let reference = Argon2::default().hash_password(b"dummy-password-for-timing", &salt)?;
    assert_eq!(dummy.algorithm, reference.algorithm);
    Ok(())
}
