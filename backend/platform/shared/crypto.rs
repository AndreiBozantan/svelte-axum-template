#[must_use]
pub fn get_hash_as_hex(token: &str) -> String {
    use sha2::Digest;

    let mut hasher = sha2::Sha256::new();
    hasher.update(token);
    hex::encode(hasher.finalize())
}

use argon2::password_hash as ar2;
use std::sync;

const PARAMS: argon2::Params = match argon2::Params::new(19_456, 2, 1, None) {
    Ok(p) => p,
    Err(_) => panic!("Invalid Argon2 parameters"),
};

fn argon2() -> argon2::Argon2<'static> {
    argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, PARAMS)
}

/// Hash a password using Argon2
pub fn hash_password(password: &str) -> Result<String, ar2::Error> {
    use ar2::PasswordHasher;
    let salt = ar2::SaltString::generate(ar2::rand_core::OsRng);
    let hash = argon2().hash_password(password.as_bytes(), &salt)?;
    Ok(hash.to_string())
}

/// Verify a password against a hash
pub fn verify_password(
    password: &str,
    hash: &str,
) -> Result<bool, ar2::Error> {
    use ar2::PasswordVerifier;
    let parsed_hash = ar2::PasswordHash::new(hash)?;
    match argon2().verify_password(password.as_bytes(), &parsed_hash) {
        Ok(()) => Ok(true),
        Err(ar2::Error::Password) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Check if a password hash needs to be re-hashed due to outdated parameters
pub fn needs_rehash(hash: &str) -> Result<bool, ar2::Error> {
    let parsed_hash = ar2::PasswordHash::new(hash)?;
    let params = argon2::Params::try_from(&parsed_hash)?;

    let is_different = parsed_hash.algorithm != argon2::Algorithm::Argon2id.ident()
        || parsed_hash.version != Some(argon2::Version::V0x13.into())
        || params.m_cost() != PARAMS.m_cost()
        || params.t_cost() != PARAMS.t_cost()
        || params.p_cost() != PARAMS.p_cost();

    Ok(is_different)
}

static DUMMY_HASH: sync::LazyLock<Result<String, ar2::Error>> =
    sync::LazyLock::new(|| hash_password("dummy_password_for_timing"));

pub fn dummy_hash() -> Result<&'static str, ar2::Error> {
    DUMMY_HASH
        .as_ref()
        .map(std::string::String::as_str)
        .map_err(ar2::Error::clone)
}

/// Compare two strings in constant time to prevent timing attacks
#[must_use]
pub fn constant_time_eq(
    a: &str,
    b: &str,
) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
