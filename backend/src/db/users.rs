use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::{self, FromRow, Type};

use crate::common;
use crate::db::{SqlContext, SqlError};

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

pub async fn create_user(db: &SqlContext, new_user: NewUser) -> Result<User, SqlError> {
    let email_normalized = common::normalize_email(&new_user.email);
    let user = sqlx::query_as!(
        User,
        r#"
        INSERT INTO users (tenant_id, status, email, password_hash, sso_provider, sso_id, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        RETURNING
            id "id!",
            tenant_id "tenant_id!",
            created_at "created_at!",
            updated_at "updated_at!",
            status "status: UserStatus",
            email "email!",
            first_name,
            middle_name,
            last_name,
            password_hash,
            sso_provider,
            sso_id,
            failed_login_count "failed_login_count!",
            last_failed_login
        "#,
        new_user.tenant_id,
        new_user.status,
        email_normalized,
        new_user.password_hash,
        new_user.sso_provider,
        new_user.sso_id,
    )
    .fetch_one(db)
    .await?;
    Ok(user)
}

pub async fn update_user_email_and_password(
    db: &SqlContext,
    user_id: i64,
    email: &str,
    password_hash: &str,
) -> Result<(), SqlError> {
    let email_normalized = common::normalize_email(email);

    let result = sqlx::query!(
        r#"
        UPDATE users 
        SET email = ?, password_hash = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        "#,
        email_normalized,
        password_hash,
        user_id
    )
    .execute(db)
    .await?;

    // If no rows were updated, the user didn't exist
    if result.rows_affected() == 0 {
        return Err(SqlError::RowNotFound);
    }

    Ok(())
}

pub async fn get_user_by_id(db: &SqlContext, id: i64) -> Result<User, SqlError> {
    let user = sqlx::query_as!(
        User,
        r#"
        SELECT
            id "id!",
            tenant_id "tenant_id!",
            created_at "created_at!",
            updated_at "updated_at!",
            status "status: UserStatus",
            email "email!",
            first_name,
            middle_name,
            last_name,
            password_hash,
            sso_provider,
            sso_id,
            failed_login_count "failed_login_count!",
            last_failed_login
        FROM users
        WHERE id = ?
        "#,
        id
    )
    .fetch_one(db)
    .await?;
    Ok(user)
}

pub async fn get_user_by_email(db: &SqlContext, email: &str) -> Result<User, SqlError> {
    let email = common::normalize_email(email);
    let user = sqlx::query_as!(
        User,
        r#"
        SELECT
            id "id!",
            tenant_id "tenant_id!",
            created_at "created_at!",
            updated_at "updated_at!",
            status "status: UserStatus",
            email "email!",
            first_name,
            middle_name,
            last_name,
            password_hash,
            sso_provider,
            sso_id,
            failed_login_count "failed_login_count!",
            last_failed_login
        FROM users
        WHERE email = ?
        "#,
        email
    )
    .fetch_one(db)
    .await?;
    Ok(user)
}

pub async fn get_user_by_sso_id(db: &SqlContext, sso_provider: &str, sso_id: &str) -> Result<User, SqlError> {
    let user = sqlx::query_as!(
        User,
        r#"
        SELECT
            id "id!",
            tenant_id "tenant_id!",
            created_at "created_at!",
            updated_at "updated_at!",
            status "status: UserStatus",
            email "email!",
            first_name,
            middle_name,
            last_name,
            password_hash,
            sso_provider,
            sso_id,
            failed_login_count "failed_login_count!",
            last_failed_login
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

pub async fn get_users_by_tenant_id(
    db: &SqlContext,
    tenant_id: i64,
    limit: i64,
    offset: i64,
) -> Result<Vec<User>, SqlError> {
    let users = sqlx::query_as!(
        User,
        r#"
        SELECT
            id "id!",
            tenant_id "tenant_id!",
            created_at "created_at!",
            updated_at "updated_at!",
            status "status: UserStatus",
            email "email!",
            first_name,
            middle_name,
            last_name,
            password_hash,
            sso_provider,
            sso_id,
            failed_login_count "failed_login_count!",
            last_failed_login
        FROM users
        WHERE tenant_id = ?
        ORDER BY id ASC
        LIMIT ? OFFSET ?
        "#,
        tenant_id,
        limit,
        offset,
    )
    .fetch_all(db)
    .await?;
    Ok(users)
}

pub async fn count_users_by_tenant_id(db: &SqlContext, tenant_id: i64) -> Result<i64, SqlError> {
    let row = sqlx::query!("SELECT COUNT(*) as count FROM users WHERE tenant_id = ?", tenant_id)
        .fetch_one(db)
        .await?;
    Ok(row.count)
}
pub async fn create_or_link_sso_user(
    db: &SqlContext,
    email: &str,
    tenant_id: i64,
    sso_provider: &str,
    sso_id: &str,
) -> Result<User, SqlError> {
    let email = common::normalize_email(email);
    let user = sqlx::query_as!(
        User,
        r#"
        INSERT INTO users (tenant_id, status, email, sso_provider, sso_id, created_at, updated_at)
        VALUES (?, 'active', ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        ON CONFLICT (email) DO UPDATE SET
            sso_provider = excluded.sso_provider,
            sso_id = excluded.sso_id,
            updated_at = CURRENT_TIMESTAMP
        RETURNING
            id "id!",
            tenant_id "tenant_id!",
            created_at "created_at!",
            updated_at "updated_at!",
            status "status: UserStatus",
            email "email!",
            first_name,
            middle_name,
            last_name,
            password_hash,
            sso_provider,
            sso_id,
            failed_login_count "failed_login_count!",
            last_failed_login
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

/// Increment failed login count using a sliding window.
///
/// If the last failure was outside the window, the count resets to 1.
/// The window duration (15 min) must match `AUTH_FAILED_LOGIN_WINDOW_MINUTES` in routes/auth.rs.
pub async fn increment_failed_login(db: &SqlContext, user_id: i64) -> Result<(), SqlError> {
    // create the modifier string, e.g., "-15 minutes"
    let window_length = format!("-{} minutes", common::constants::auth::FAILED_LOGIN_WINDOW_MINUTES);

    sqlx::query!(
        r#"
        UPDATE users SET
            failed_login_count = CASE
                WHEN last_failed_login > datetime('now', ?) THEN failed_login_count + 1
                ELSE 1
            END,
            last_failed_login = CURRENT_TIMESTAMP
        WHERE id = ?
        "#,
        window_length,
        user_id
    )
    .execute(db)
    .await?;
    Ok(())
}

/// Reset the failed login counter on successful authentication.
pub async fn reset_failed_login(db: &SqlContext, user_id: i64) -> Result<(), SqlError> {
    sqlx::query!(
        r#"
        UPDATE users SET
            failed_login_count = 0,
            last_failed_login = NULL
        WHERE id = ?
        "#,
        user_id
    )
    .execute(db)
    .await?;
    Ok(())
}
