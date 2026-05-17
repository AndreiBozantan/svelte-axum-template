use argon2::Argon2;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHasher, SaltString};

use crate::auth::{self, hash_password, verify_password};

#[test]
fn test_hash_password_creates_valid_hash() {
    let password = "test_password_123";
    let hash = hash_password(password).unwrap();
    assert!(hash.starts_with("$argon2id$")); // argon2 hash should start with $argon2id$
    assert!(hash.len() > 50); // hash should be non-empty and have reasonable length
}

#[test]
fn test_hash_password_generates_different_hashes() {
    let password = "same_password";
    let hash1 = hash_password(password).unwrap();
    let hash2 = hash_password(password).unwrap();
    assert_ne!(hash1, hash2); // different salts should produce different hashes
}

#[test]
fn test_verify_password_success() {
    let password = "correct_password";
    let hash = hash_password(password).unwrap();
    let result = verify_password(password, &hash).unwrap();
    assert!(result);
}

#[test]
fn test_verify_password_failure() {
    let password = "correct_password";
    let wrong_password = "wrong_password";
    let hash = hash_password(password).unwrap();
    let result = verify_password(wrong_password, &hash).unwrap();
    assert!(!result);
}

#[test]
fn test_verify_password_with_invalid_hash() {
    let password = "any_password";
    let invalid_hash = "not_a_valid_hash";
    let result = verify_password(password, invalid_hash);
    assert!(result.is_err());
}

#[test]
fn test_hash_empty_password() {
    let password = "";
    let hash = hash_password(password).unwrap();
    let result = verify_password(password, &hash).unwrap();
    assert!(result);
}

#[test]
fn test_hash_long_password() {
    let password = "a".repeat(1000); // Very long password
    let hash = hash_password(&password).unwrap();
    let result = verify_password(&password, &hash).unwrap();
    assert!(result);
}

#[test]
fn test_hash_unicode_password() {
    let password = "🔐密码测试🔑";
    let hash = hash_password(password).unwrap();
    let result = verify_password(password, &hash).unwrap();
    assert!(result);
}

#[test]
fn dummy_hash_parameters_match_argon2_default() {
    // Parse both hashes and compare their parameters
    let salt = SaltString::generate(&mut OsRng);
    let fresh = Argon2::default().hash_password(b"test", &salt).expect("hash failed");
    let dummy = argon2::PasswordHash::new(auth::DUMMY_HASH).expect("dummy hash is valid");

    assert_eq!(dummy.algorithm, fresh.algorithm, 
        "DUMMY_HASH algorithm does not match Argon2::default() — regenerate the constant");
    assert_eq!(dummy.version, fresh.version,
        "DUMMY_HASH version does not match Argon2::default() — regenerate the constant");
    assert_eq!(dummy.params, fresh.params,
        "DUMMY_HASH params (m, t, p) do not match Argon2::default() — regenerate the constant");
}