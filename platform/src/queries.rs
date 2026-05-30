use chrono::Utc;
use sqlx::sqlite::SqliteQueryResult;

use crate::utils;
use crate::constants::auth;
use crate::db::SqlContext;
use crate::db::SqlError;
use crate::models::*;

// ==================== Users ====================

pub async fn create_user(db: &SqlContext, new_user: NewUser) -> Result<User, SqlError> {
    let email_normalized = utils::normalize_email(&new_user.email);
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
    let email_normalized = utils::normalize_email(email);

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
    let email = utils::normalize_email(email);
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
    let email = utils::normalize_email(email);
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
    let window_length = format!("-{} minutes", auth::FAILED_LOGIN_WINDOW_MINUTES);

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

// ==================== Refresh Tokens ====================

pub async fn create_refresh_token(db: &SqlContext, new_refresh_token: NewRefreshToken) -> Result<(), SqlError> {
    sqlx::query!(
        r#"
        INSERT INTO refresh_tokens (jti, tenant_id, user_id, token_hash, issued_at, expires_at)
        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, ?)
        "#,
        new_refresh_token.jti,
        new_refresh_token.tenant_id,
        new_refresh_token.user_id,
        new_refresh_token.token_hash,
        new_refresh_token.expires_at
    )
    .execute(db)
    .await?;
    Ok(())
}

pub async fn revoke_refresh_token(db: &SqlContext, jti: &str) -> Result<(), SqlError> {
    sqlx::query!(
        r#"
        UPDATE refresh_tokens
        SET revoked_at = CURRENT_TIMESTAMP
        WHERE jti = ?
        "#,
        jti
    )
    .execute(db)
    .await?;
    Ok(())
}

pub async fn get_refresh_token_by_jti(db: &SqlContext, tenant_id: i64, jti: &str) -> Result<RefreshToken, SqlError> {
    let token = sqlx::query_as!(
        RefreshToken,
        r#"
        SELECT
            id "id!",
            jti "jti!",
            user_id "user_id!",
            token_hash "token_hash!",
            issued_at "issued_at!",
            expires_at "expires_at!",
            revoked_at
        FROM refresh_tokens
        WHERE tenant_id = ? AND jti = ?
        "#,
        tenant_id,
        jti
    )
    .fetch_one(db)
    .await?;
    Ok(token)
}

pub async fn revoke_all_refresh_tokens_for_user(
    db: &SqlContext,
    tenant_id: i64,
    user_id: i64,
) -> Result<SqliteQueryResult, SqlError> {
    let now = Utc::now().naive_utc();
    let result = sqlx::query!(
        r#"
        UPDATE refresh_tokens
        SET revoked_at = ?
        WHERE tenant_id = ? AND user_id = ? AND revoked_at IS NULL
        "#,
        now,
        tenant_id,
        user_id,
    )
    .execute(db)
    .await?;
    Ok(result)
}

/// Cleanup expired refresh tokens
/// TODO: add a way to use this (e.g. command in CLI and scheduled task in server or a background task)
async fn _cleanup_expired(db: &SqlContext) -> Result<SqliteQueryResult, SqlError> {
    let now = Utc::now().naive_utc();
    let result = sqlx::query!(
        r#"
        DELETE FROM refresh_tokens
        WHERE expires_at < ?
        "#,
        now
    )
    .execute(db)
    .await?;
    Ok(result)
}

// ==================== Tenants ====================

pub async fn get_tenant_by_id(db: &SqlContext, id: i64) -> Result<Tenant, SqlError> {
    let tenant = sqlx::query_as!(
        Tenant,
        r#"
        SELECT
            id as "id!",
            status as "status: TenantStatus",
            name as "name!",
            description,
            created_at as "created_at!",
            updated_at as "updated_at!"
        FROM tenants
        WHERE id = ?
        "#,
        id
    )
    .fetch_one(db)
    .await?;
    Ok(tenant)
}
