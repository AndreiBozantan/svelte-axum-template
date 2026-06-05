use chrono::NaiveDateTime;
use sqlx::FromRow;

use crate::common;
use crate::identity::tokens;

#[derive(Debug, FromRow)]
#[allow(dead_code)]
struct RefreshTokenRow {
    id: i64,
    jti: String,
    user_id: i64,
    token_hash: String,
    issued_at: NaiveDateTime,
    expires_at: NaiveDateTime,
    revoked_at: Option<NaiveDateTime>,
}

impl From<RefreshTokenRow> for tokens::RefreshToken {
    fn from(row: RefreshTokenRow) -> Self {
        Self {
            user_id: common::UserId(row.user_id),
            token_hash: row.token_hash,
            revoked_at: row.revoked_at,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Repository;

impl tokens::TRepository for Repository {
    async fn create(
        &self,
        db: &common::SqlContext,
        command: tokens::CreateRefreshTokenCommand,
    ) -> Result<(), common::RepoError> {
        sqlx::query!(
            r#"
            INSERT INTO refresh_tokens (jti, tenant_id, user_id, token_hash, issued_at, expires_at)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, ?)
            "#,
            command.jti,
            command.tenant_id.0,
            command.user_id.0,
            command.token_hash,
            command.expires_at
        )
        .execute(db)
        .await?;
        Ok(())
    }

    async fn revoke_by_jti(&self, db: &common::SqlContext, jti: &str) -> Result<(), common::RepoError> {
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

    async fn find_by_jti(
        &self,
        db: &common::SqlContext,
        tenant_id: common::TenantId,
        jti: &str,
    ) -> Result<tokens::RefreshToken, common::RepoError> {
        let row = sqlx::query_as!(
            RefreshTokenRow,
            r#"
            SELECT
                id as "id!",
                jti as "jti!",
                user_id as "user_id!",
                token_hash as "token_hash!",
                issued_at as "issued_at!",
                expires_at as "expires_at!",
                revoked_at
            FROM refresh_tokens
            WHERE tenant_id = ? AND jti = ?
            "#,
            tenant_id.0,
            jti
        )
        .fetch_one(db)
        .await?;
        Ok(row.into())
    }

    async fn revoke_all_for_user(
        &self,
        db: &common::SqlContext,
        tenant_id: common::TenantId,
        user_id: common::UserId,
    ) -> Result<(), common::RepoError> {
        let now = chrono::Utc::now().naive_utc();
        sqlx::query!(
            r#"
            UPDATE refresh_tokens
            SET revoked_at = ?
            WHERE tenant_id = ? AND user_id = ? AND revoked_at IS NULL
            "#,
            now,
            tenant_id.0,
            user_id.0,
        )
        .execute(db)
        .await?;
        Ok(())
    }
}
