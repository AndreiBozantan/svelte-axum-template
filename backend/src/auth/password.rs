use argon2::Argon2;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{Error, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};

/// Hash a password using Argon2
pub fn hash_password(password: &str) -> Result<String, Error> {
    let salt = SaltString::generate(OsRng);
    let password_hash = Argon2::default().hash_password(password.as_bytes(), &salt)?;
    Ok(password_hash.to_string())
}

/// Verify a password against a hash
pub fn verify_password(password: &str, hash: &str) -> Result<bool, Error> {
    let parsed_hash = PasswordHash::new(hash)?;
    match Argon2::default().verify_password(password.as_bytes(), &parsed_hash) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
