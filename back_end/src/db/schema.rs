use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use std::time::SystemTime;

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct Tenant {
    pub id: i64,
    pub name: String,
    pub description: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl Tenant {
    pub fn new(id: i64, name: String, description: Option<String>) -> Self {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

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
    pub password_hash: String,
    pub email: Option<String>,
    pub tenant_id: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NewUser {
    pub username: String,
    pub password_hash: String,
    pub email: Option<String>,
    pub tenant_id: Option<i64>,
}

impl User {
    pub fn new(id: i64, username: String, password_hash: String, email: Option<String>, tenant_id: Option<i64>) -> Self {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        Self {
            id,
            username,
            password_hash,
            email,
            tenant_id,
            created_at: now,
            updated_at: now,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct ApiToken {
    pub id: i64,
    pub token: String,
    pub user_id: i64,
    pub created_at: i64,
    pub expires_at: Option<i64>,
}

impl ApiToken {
    pub fn new(id: i64, token: String, user_id: i64, expires_at: Option<i64>) -> Self {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        Self {
            id,
            token,
            user_id,
            created_at: now,
            expires_at,
        }
    }
}