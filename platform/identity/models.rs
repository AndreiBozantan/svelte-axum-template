use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::{self, FromRow, Type};

// ---- Users ----

#[derive(Debug, PartialEq, Eq, Type, Serialize, Deserialize)]
#[sqlx(type_name = "TEXT", rename_all = "lowercase")]
pub enum UserStatus {
    Onboarding,
    Active,
    Suspended,
    Archived,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: i64,
    pub tenant_id: i64,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
    pub status: UserStatus,
    pub email: String,
    pub first_name: Option<String>,
    pub middle_name: Option<String>,
    pub last_name: Option<String>,
    pub password_hash: Option<String>,
    pub sso_provider: Option<String>,
    pub sso_id: Option<String>,
    pub failed_login_count: i64,
    pub last_failed_login: Option<NaiveDateTime>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NewUser {
    pub tenant_id: i64,
    pub status: UserStatus,
    pub email: String,
    pub first_name: Option<String>,
    pub middle_name: Option<String>,
    pub last_name: Option<String>,
    pub password_hash: Option<String>,
    pub sso_provider: Option<String>,
    pub sso_id: Option<String>,
}

// ---- Refresh Tokens ----

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
    pub tenant_id: i64,
    pub user_id: i64,
    pub token_hash: String,
    pub expires_at: NaiveDateTime,
}

// ---- Tenants ----

#[derive(Debug, PartialEq, Eq, Type, Serialize, Deserialize)]
#[sqlx(type_name = "TEXT", rename_all = "lowercase")]
pub enum TenantStatus {
    Active,
    Suspended,
    Archived,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct Tenant {
    pub id: i64,
    pub status: TenantStatus,
    pub name: String,
    pub description: Option<String>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NewTenant {
    pub status: TenantStatus,
    pub name: String,
    pub description: Option<String>,
}
