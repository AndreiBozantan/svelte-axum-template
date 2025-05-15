use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use std::time::SystemTime;

// Helper function to get current timestamp
pub fn current_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

// JWT Claims structure
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,        // Subject (user ID or username)
    pub exp: i64,           // Expiration time
    pub iat: i64,           // Issued at time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<i64>, // Optional tenant ID
    pub jti: String,        // JWT ID (to prevent replay attacks)
}

impl Claims {
    pub fn new(username: &str, tenant_id: Option<i64>, exp_minutes: i64) -> Self {
        let now = Utc::now();
        Self {
            sub: username.to_owned(),
            exp: (now + Duration::minutes(exp_minutes)).timestamp(),
            iat: now.timestamp(),
            tenant_id,
            jti: Uuid::new_v4().to_string(),
        }
    }
}

// Config structure for JWT
#[derive(Clone, Debug)]
pub struct JwtConfig {
    pub secret: String,
    pub access_token_expiry_mins: i64,
    pub refresh_token_expiry_mins: i64,
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            secret: "your-jwt-secret-key-should-be-very-long-and-secure".to_owned(),
            access_token_expiry_mins: 15,     // 15 minutes
            refresh_token_expiry_mins: 1440,  // 24 hours
        }
    }
}

pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(password.as_bytes(), &salt)?;
    Ok(password_hash.to_string())
}

pub fn verify_password(hash: &str, password: &str) -> bool {
    match PasswordHash::new(hash) {
        Ok(parsed_hash) => {
            let argon2 = Argon2::default();
            argon2
                .verify_password(password.as_bytes(), &parsed_hash)
                .is_ok()
        }
        Err(_) => false,
    }
}

pub fn generate_random_token() -> String {
    Uuid::new_v4().to_string()
}

pub fn create_jwt(claims: &Claims, jwt_config: &JwtConfig) -> Result<String, jsonwebtoken::errors::Error> {
    encode(
        &Header::default(),
        claims,
        &EncodingKey::from_secret(jwt_config.secret.as_bytes()),
    )
}

pub fn validate_jwt(token: &str, jwt_config: &JwtConfig) -> Result<Claims, jsonwebtoken::errors::Error> {
    let validation = Validation::default();
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(jwt_config.secret.as_bytes()),
        &validation,
    )?;
    Ok(token_data.claims)
}

// Function to determine if a token has expired
pub fn is_token_expired(expires_at: Option<i64>) -> bool {
    match expires_at {
        Some(exp) => current_timestamp() > exp,
        None => false, // If no expiration, token doesn't expire
    }
}
