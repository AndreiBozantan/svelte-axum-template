use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

use crate::core::{DbContext, DbError};

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: i64,
    pub tenant_id: i64,
    pub email: String,
    pub password_hash: Option<String>, // Nullable for SSO users
    pub sso_provider: Option<String>,
    pub sso_id: Option<String>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NewUser {
    pub tenant_id: i64,
    pub email: String,
    pub password_hash: Option<String>, // Nullable for SSO users
    pub sso_provider: Option<String>,
    pub sso_id: Option<String>,
}

pub async fn create_user(db: &DbContext, new_user: NewUser) -> Result<User, DbError> {
    let user = sqlx::query_as!(
        User,
        r#"
        INSERT INTO users (tenant_id, email, password_hash, sso_provider, sso_id, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        RETURNING
            id as "id!",
            tenant_id as "tenant_id!",
            email as "email!",
            password_hash,
            sso_provider,
            sso_id,
            created_at as "created_at!",
            updated_at as "updated_at!"
        "#,
        new_user.tenant_id,
        new_user.email,
        new_user.password_hash,
        new_user.sso_provider,
        new_user.sso_id,
    )
    .fetch_one(db)
    .await?;
    Ok(user)
}

pub async fn get_user_by_id(db: &DbContext, id: i64) -> Result<User, DbError> {
    let user = sqlx::query_as!(
        User,
        r#"
        SELECT
            id "id!",
            tenant_id "tenant_id!",
            email "email!",
            password_hash,
            sso_provider,
            sso_id,
            created_at "created_at!",
            updated_at "updated_at!"
        FROM users
        WHERE id = ?
        "#,
        id
    )
    .fetch_one(db)
    .await?;
    Ok(user)
}

pub async fn get_user_by_email(db: &DbContext, email: &str) -> Result<User, DbError> {
    let user = sqlx::query_as!(
        User,
        r#"
        SELECT
            id "id!",
            tenant_id "tenant_id!",
            email "email!",
            password_hash,
            sso_provider,
            sso_id,
            created_at "created_at!",
            updated_at "updated_at!"
        FROM users
        WHERE email = ?
        "#,
        email
    )
    .fetch_one(db)
    .await?;
    Ok(user)
}

pub async fn get_user_by_sso_id(db: &DbContext, sso_provider: &str, sso_id: &str) -> Result<User, DbError> {
    let user = sqlx::query_as!(
        User,
        r#"
        SELECT
            id "id!",
            tenant_id "tenant_id!",
            email "email!",
            password_hash,
            sso_provider,
            sso_id,
            created_at "created_at!",
            updated_at "updated_at!"
        FROM users
        WHERE sso_provider = ? AND sso_id = ?
        "#,
        sso_provider,
        sso_id,
    )
    .fetch_one(db)
    .await?;
    Ok(user)
}

pub async fn create_or_link_sso_user(
    db: &DbContext,
    email: &str,
    tenant_id: i64,
    sso_provider: &str,
    sso_id: &str,
) -> Result<User, DbError> {
    let user = sqlx::query_as!(
        User,
        r#"
        INSERT INTO users (tenant_id, email, sso_provider, sso_id, created_at, updated_at)
        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        ON CONFLICT (email) DO UPDATE SET
            sso_provider = excluded.sso_provider,
            sso_id = excluded.sso_id,
            updated_at = CURRENT_TIMESTAMP
        RETURNING
            id "id!",
            tenant_id "tenant_id!",
            email "email!",
            password_hash,
            sso_provider,
            sso_id,
            created_at "created_at!",
            updated_at "updated_at!"
        "#,
        tenant_id,
        email,
        sso_provider,
        sso_id
    )
    .fetch_one(db)
    .await?;
    Ok(user)
}
