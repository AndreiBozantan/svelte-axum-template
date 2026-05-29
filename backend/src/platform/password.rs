use argon2::Argon2;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::Error;
use argon2::password_hash::PasswordHash;
use argon2::password_hash::PasswordHasher;
use argon2::password_hash::PasswordVerifier;
use argon2::password_hash::SaltString;

/// Hash a password using Argon2
pub fn hash_password(password: &str) -> Result<String, Error> {
    let salt = SaltString::generate(OsRng);
    let hash = Argon2::default().hash_password(password.as_bytes(), &salt)?;
    Ok(hash.to_string())
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

/// A pre-computed Argon2 hash of a dummy password, used to perform a
/// constant-time "wasted" verify when the requested user does not exist,
/// preventing user-enumeration via response-time differences.
pub static DUMMY_HASH: &str = "$argon2id$\
    v=19$m=19456,t=2,p=1$\
    HfRKx+hpIQ18rfUQ5TuA5g$Zq2p1OruNc6cZAgJmgnTIs3XpBLKdrM/DujpWOPAMwQ"; // semgrep: ignore
