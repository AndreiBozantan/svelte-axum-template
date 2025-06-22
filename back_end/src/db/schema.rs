use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct Tenant {
    pub id: i64,
    pub name: String,
    pub description: Option<String>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
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