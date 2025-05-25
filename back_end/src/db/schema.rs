use chrono::{NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use std::time::SystemTime;

pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct Tenant {
    pub id: i64,
    pub name: String,
    pub description: Option<String>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

impl Tenant {
    pub fn new(id: i64, name: String, description: Option<String>) -> Self {
        let now = Utc::now().naive_utc();
        Self {
            id,
            name,
            description,
            created_at: now,
            updated_at: now,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NewTenant {
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub password_hash: Option<String>, // Nullable for SSO users
    pub email: Option<String>,
    pub tenant_id: Option<i64>,
    pub sso_provider: Option<String>,
    pub sso_id: Option<String>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NewUser {
    pub username: String,
    pub password_hash: Option<String>, // Nullable for SSO users
    pub email: Option<String>,
    pub tenant_id: Option<i64>,
    pub sso_provider: Option<String>,
    pub sso_id: Option<String>,
}

impl User {
    pub fn new(id: i64, username: String, password_hash: Option<String>, email: Option<String>, tenant_id: Option<i64>) -> Self {
        let now = Utc::now().naive_utc();
        Self {
            id,
            username,
            password_hash,
            email,
            tenant_id,
            sso_provider: None,
            sso_id: None,
            created_at: now,
            updated_at: now,
        }
    }
}


#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct RefreshToken {
    pub id: i64,
    pub jti: String,
    pub user_id: i64,
    pub token_hash: String,
    pub issued_at: NaiveDateTime,
    pub expires_at: NaiveDateTime,
    pub revoked_at: Option<NaiveDateTime>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NewRefreshToken {
    pub jti: String,
    pub user_id: i64,
    pub token_hash: String,
    pub expires_at: NaiveDateTime,
}