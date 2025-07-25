use chrono::NaiveDateTime;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use sqlx::sqlite::SqliteQueryResult;

use crate::core::{DbContext, DbError};

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

pub async fn create_refresh_token(db: &DbContext, new_refresh_token: NewRefreshToken) -> Result<(), DbError> {
    sqlx::query!(
        r#"
        INSERT INTO refresh_tokens (jti, user_id, token_hash, issued_at, expires_at)
        VALUES (?, ?, ?, CURRENT_TIMESTAMP, ?)
        "#,
        new_refresh_token.jti,
        new_refresh_token.user_id,
        new_refresh_token.token_hash,
        new_refresh_token.expires_at
    )
    .execute(db)
    .await?;
    Ok(())
}

pub async fn revoke_refresh_token(db: &DbContext, jti: &str) -> Result<(), DbError> {
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

pub async fn get_refresh_token_by_jti(db: &DbContext, jti: &str) -> Result<RefreshToken, DbError> {
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
        WHERE jti = ? AND revoked_at IS NULL
        "#,
        jti
    )
    .fetch_one(db)
    .await?;
    Ok(token)
}

pub async fn revoke_all_refresh_tokens_for_user(db: &DbContext, user_id: i64) -> Result<SqliteQueryResult, DbError> {
    let now = Utc::now().naive_utc();
    let result = sqlx::query!(
        r#"
        UPDATE refresh_tokens
        SET revoked_at = ?
        WHERE user_id = ? AND revoked_at IS NULL
        "#,
        now,
        user_id
    )
    .execute(db)
    .await?;
    Ok(result)
}

/// Cleanup expired refresh tokens
/// TODO: add a way to use this (e.g. scheduled task)
async fn _cleanup_expired(db: &DbContext) -> Result<SqliteQueryResult, DbError> {
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
