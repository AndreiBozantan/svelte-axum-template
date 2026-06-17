use chrono::NaiveDateTime;
use sqlx::FromRow;

use crate::platform::common;
use crate::platform::db;
use crate::platform::identity::tokens;

#[derive(Debug, FromRow)]
#[allow(dead_code)]
struct Row {
    id: i64,
    jti: String,
    user_id: i64,
    token_hash: String,
    issued_at: NaiveDateTime,
    expires_at: NaiveDateTime,
    revoked_at: Option<NaiveDateTime>,
}

impl From<Row> for tokens::RefreshToken {
    fn from(row: Row) -> Self {
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
        db: &db::Context,
        command: tokens::CreateRefreshTokenCommand,
    ) -> Result<(), db::Error> {
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

    async fn revoke_by_jti(
        &self,
        db: &db::Context,
        tenant_id: common::TenantId,
        jti: &str,
    ) -> Result<(), db::Error> {
        let epoch = chrono::DateTime::from_timestamp(0, 0)
            .map(|dt| dt.naive_utc())
            .ok_or_else(|| db::Error::DatabaseOperationFailed(sqlx::Error::Protocol("invalid epoch".into())))?;
        let result = sqlx::query!(
            r#"
            UPDATE refresh_tokens
            SET revoked_at = ?
            WHERE jti = ? AND tenant_id = ?
            "#,
            epoch,
            jti,
            tenant_id.0
        )
        .execute(db)
        .await?;

        if result.rows_affected() == 0 {
            return Err(db::Error::RowNotFound);
        }
        Ok(())
    }

    async fn try_revoke_active_by_jti(
        &self,
        db: &db::Context,
        tenant_id: common::TenantId,
        jti: &str,
    ) -> Result<Option<tokens::RefreshToken>, db::Error> {
        let row = sqlx::query_as!(
            Row,
            r#"
            UPDATE refresh_tokens
            SET revoked_at = CURRENT_TIMESTAMP
            WHERE tenant_id = ? AND jti = ? AND revoked_at IS NULL
            RETURNING
                id as "id!",
                jti as "jti!",
                user_id as "user_id!",
                token_hash as "token_hash!",
                issued_at as "issued_at!",
                expires_at as "expires_at!",
                revoked_at
            "#,
            tenant_id.0,
            jti
        )
        .fetch_optional(db)
        .await?;
        Ok(row.map(Into::into))
    }

    async fn find_by_jti(
        &self,
        db: &db::Context,
        tenant_id: common::TenantId,
        jti: &str,
    ) -> Result<tokens::RefreshToken, db::Error> {
        let row = sqlx::query_as!(
            Row,
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
        db: &db::Context,
        tenant_id: common::TenantId,
        user_id: common::UserId,
    ) -> Result<(), db::Error> {
        let epoch = chrono::DateTime::from_timestamp(0, 0)
            .map(|dt| dt.naive_utc())
            .ok_or_else(|| db::Error::DatabaseOperationFailed(sqlx::Error::Protocol("invalid epoch".into())))?;
        sqlx::query!(
            r#"
            UPDATE refresh_tokens
            SET revoked_at = ?
            WHERE tenant_id = ? AND user_id = ? AND revoked_at IS NULL
            "#,
            epoch,
            tenant_id.0,
            user_id.0,
        )
        .execute(db)
        .await?;
        Ok(())
    }

    async fn delete_expired(
        &self,
        db: &db::Context,
        now: NaiveDateTime,
    ) -> Result<u64, db::Error> {
        let result = sqlx::query!(
            r#"
            DELETE FROM refresh_tokens
            WHERE expires_at < ?
            "#,
            now
        )
        .execute(db)
        .await?;
        Ok(result.rows_affected())
    }
}
