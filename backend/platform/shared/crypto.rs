#[must_use]
pub fn get_token_hash_as_hex(token: &str) -> String {
    use sha2::Digest;

    let mut hasher = sha2::Sha256::new();
    hasher.update(token);
    hex::encode(hasher.finalize())
}

use argon2::password_hash as ar2;
use std::sync;

/// Hash a password using Argon2
pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    use ar2::PasswordHasher;
    const ARGON2_MEM_COST: u32 = 19456;
    const ARGON2_TIME_COST: u32 = 2;
    const ARGON2_PARALLELISM: u32 = 1;
    let salt = ar2::SaltString::generate(ar2::rand_core::OsRng);
    let params = argon2::Params::new(ARGON2_MEM_COST, ARGON2_TIME_COST, ARGON2_PARALLELISM, None)?;
    let hasher = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let hash = hasher.hash_password(password.as_bytes(), &salt)?;
    Ok(hash.to_string())
}

/// Verify a password against a hash
pub fn verify_password(
    password: &str,
    hash: &str,
) -> Result<bool, ar2::Error> {
    use ar2::PasswordVerifier;
    use argon2::Argon2;
    let parsed_hash = ar2::PasswordHash::new(hash)?;
    match Argon2::default().verify_password(password.as_bytes(), &parsed_hash) {
        Ok(()) => Ok(true),
        Err(ar2::Error::Password) => Ok(false),
        Err(e) => Err(e),
    }
}

static DUMMY_HASH: sync::LazyLock<Result<String, ar2::Error>> =
    sync::LazyLock::new(|| hash_password("dummy_password_for_timing"));

pub fn dummy_hash() -> Result<&'static str, ar2::Error> {
    DUMMY_HASH
        .as_ref()
        .map(std::string::String::as_str)
        .map_err(ar2::Error::clone)
}
