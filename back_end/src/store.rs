use chrono::{Utc, NaiveDateTime};
use sqlx::sqlite::SqliteQueryResult;
use thiserror::Error;

use crate::db::DbPool;
use crate::db::schema::{NewRefreshToken, NewTenant, NewUser, RefreshToken, Tenant, User };

// TODO: split the store module in separate files for each table

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("User not found")]
    UserNotFound,

    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Token not found")]
    TokenNotFound,

    #[error("Tenant not found")]
    TenantNotFound,
}

#[derive(Clone, Debug)]
pub struct Store {
    db_pool: DbPool,
}

impl Store {
    pub fn new(db_pool: DbPool) -> Self {
        Self {
            db_pool,
        }
    }

    // User operations
    pub async fn create_user(&self, new_user: NewUser) -> Result<User, StoreError> {
        let user = sqlx::query_as!(
            User,
            r#"
            INSERT INTO users (username, password_hash, email, tenant_id, sso_provider, sso_id, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, strftime('%s', 'now'), strftime('%s', 'now'))
            RETURNING id, username, password_hash, email, tenant_id, sso_provider, sso_id, created_at, updated_at
            "#,
            new_user.username,
            new_user.password_hash,
            new_user.email,
            new_user.tenant_id,
            new_user.sso_provider,
            new_user.sso_id)
        .fetch_one(&self.db_pool)
        .await?;

        return Ok(user);
    }

    pub async fn get_user_by_id(&self, id: i64) -> Result<User, StoreError> {
        let user = sqlx::query_as!(
            User,
            r#"
            SELECT
                id "id!",
                username "username!",
                password_hash,
                email,
                tenant_id,
                sso_provider,
                sso_id,
                created_at "created_at!",
                updated_at "updated_at!"
            FROM users
            WHERE id = ?
            "#,
            id
        )
        .fetch_one(&self.db_pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => StoreError::UserNotFound,
            _ => StoreError::Database(e),
        })?;

        return Ok(user);
    }

    pub async fn get_user_by_username(&self, username: &str) -> Result<User, StoreError> {
        let user = sqlx::query_as!(
            User,
            r#"
            SELECT
                id "id!",
                username "username!",
                password_hash,
                email,
                tenant_id,
                sso_provider,
                sso_id,
                created_at "created_at!",
                updated_at "updated_at!"
            FROM users
            WHERE username = ?
            "#,
            username
        )
        .fetch_one(&self.db_pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => StoreError::UserNotFound,
            _ => StoreError::Database(e),
        })?;
        return Ok(user);
    }

    // JWT Token audit and refresh token operations
    pub async fn store_refresh_token(&self, new_refresh_token: NewRefreshToken) -> Result<(), StoreError> {
        sqlx::query!(
            r#"
            INSERT INTO refresh_tokens (jti, user_id, token_hash, issued_at, expires_at)
            VALUES (?, ?, ?, strftime('%s', 'now'), ?)
            "#,
            new_refresh_token.jti,
            new_refresh_token.user_id,
            new_refresh_token.token_hash,
            new_refresh_token.expires_at
        )
        .execute(&self.db_pool)
        .await?;
        Ok(())
    }

    pub async fn revoke_refresh_token(&self, jti: &str) -> Result<(), StoreError> {
        sqlx::query!(
            r#"
            UPDATE refresh_tokens
            SET revoked_at = strftime('%s', 'now')
            WHERE jti = ?
            "#,
            jti
        )
        .execute(&self.db_pool)
        .await?;
        Ok(())
    }

    pub async fn is_refresh_token_revoked(&self, jti: &str) -> Result<bool, StoreError> {
        let result = sqlx::query!(
            r#"
            SELECT revoked_at FROM refresh_tokens
            WHERE jti = ?
            "#,
            jti
        )
        .fetch_optional(&self.db_pool)
        .await?;

        // If token doesn't exist or has revoked_at set, it's considered revoked
        Ok(match result {
            Some(row) => row.revoked_at.is_some(),
            None => true, // Token not found = revoked
        })
    }

    pub async fn audit_access_token(&self, jti: &str, user_id: i64, issued_at: NaiveDateTime, expires_at: NaiveDateTime, user_agent: Option<&str>, ip_address: Option<&str>) -> Result<(), StoreError> {
        sqlx::query!(
            r#"
            INSERT INTO access_token_audit (jti, user_id, issued_at, expires_at, user_agent, ip_address)
            VALUES (?, ?, ?, ?, ?, ?)
            "#,
            jti,
            user_id,
            issued_at,
            expires_at,
            user_agent,
            ip_address
        )
        .execute(&self.db_pool)
        .await?;
        Ok(())
    }

    pub async fn is_access_token_revoked(&self, jti: &str) -> Result<bool, StoreError> {
        // For now, we can check if the associated refresh token was revoked
        // In a more advanced implementation, you might also track access token revocations
        let result = sqlx::query!(
            r#"
            SELECT r.revoked_at
            FROM access_token_audit a
            JOIN refresh_tokens r ON a.user_id = r.user_id
            WHERE a.jti = ?
            AND r.expires_at > strftime('%s', 'now')
            ORDER BY r.issued_at DESC
            LIMIT 1
            "#,
            jti
        )
        .fetch_optional(&self.db_pool)
        .await?;

        // If we can't find an active refresh token, consider the access token revoked
        Ok(match result {
            Some(row) => row.revoked_at.is_some(),
            None => false, // No corresponding refresh token found, but access token may still be valid
        })
    }

    pub async fn get_tenants(&self) -> Result<Vec<Tenant>, StoreError> {
        let tenants = sqlx::query_as!(
            Tenant,
            r#"
            SELECT
                id as "id!",
                name as "name!",
                description as "description!",
                created_at as "created_at!",
                updated_at as "updated_at!"
            FROM tenants
            "#
        )
        .fetch_all(&self.db_pool)
        .await?;
        return Ok(tenants)
    }

    pub async fn get_tenant_by_id(&self, id: i64) -> Result<Tenant, StoreError> {
        let tenant = sqlx::query_as!(
            Tenant,
            r#"
            SELECT
                id as "id!",
                name as "name!",
                description as "description!",
                created_at as "created_at!",
                updated_at as "updated_at!"
            FROM tenants
            WHERE id = ?
            "#,
            id
        )
        .fetch_one(&self.db_pool)
        .await?;
        return Ok(tenant)
    }

    pub async fn create_tenant(&self, tenant: NewTenant) -> Result<Tenant, StoreError> {
        let now = Utc::now().naive_utc();
        let tenant = sqlx::query_as!(
            Tenant,
            r#"
            INSERT INTO tenants (name, description, created_at, updated_at)
            VALUES (?, ?, ?, ?)
            RETURNING id, name, description, created_at, updated_at
            "#,
            tenant.name,
            tenant.description,
            now,
            now
        )
        .fetch_one(&self.db_pool)
        .await?;
        return Ok(tenant)
    }

    pub async fn update_tenant(&self, id: i64, tenant: NewTenant) -> Result<Tenant, StoreError> {
        let now = Utc::now().naive_utc();
        let tenant = sqlx::query_as!(
            Tenant,
            r#"
            UPDATE tenants
            SET name = ?, description = ?, updated_at = ?
            WHERE id = ?
            RETURNING id, name, description, created_at, updated_at
            "#,
            tenant.name,
            tenant.description,
            now,
            id
        )
        .fetch_one(&self.db_pool)
        .await?;
        return Ok(tenant)
    }

    pub async fn delete_tenant(&self, id: i64) -> Result<SqliteQueryResult, StoreError> {
        let result = sqlx::query!(
            r#"
            DELETE FROM tenants
            WHERE id = ?
            "#,
            id
        )
        .execute(&self.db_pool)
        .await?;

        return Ok(result)
    }

    pub async fn get_users_by_tenant(&self, tenant_id: i64) -> Result<Vec<User>, StoreError> {
        let users = sqlx::query_as!(
            User,
            r#"
            SELECT
                id as "id!",
                username as "username!",
                password_hash,
                email,
                tenant_id,
                sso_provider,
                sso_id,
                created_at as "created_at!",
                updated_at as "updated_at!"
            FROM users
            WHERE tenant_id = ?
            "#,
            tenant_id
        )
        .fetch_all(&self.db_pool)
        .await?;

        return Ok(users)
    }

    pub async fn assign_user_to_tenant(&self, user_id: i64, tenant_id: i64) -> Result<SqliteQueryResult, StoreError> {
        let result = sqlx::query!(
            r#"
            UPDATE users
            SET tenant_id = ?
            WHERE id = ?
            "#,
            tenant_id,
            user_id
        )
        .execute(&self.db_pool)
        .await?;
        Ok(result)
    }

    // JWT Refresh Token operations

    pub async fn get_refresh_token_by_jti(&self, jti: &str) -> Result<RefreshToken, StoreError> {
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
        .fetch_one(&self.db_pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => StoreError::TokenNotFound,
            _ => StoreError::Database(e),
        })?;
        Ok(token)
    }

    pub async fn revoke_all_user_refresh_tokens(&self, user_id: i64) -> Result<SqliteQueryResult, StoreError> {
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
        .execute(&self.db_pool)
        .await?;
        Ok(result)
    }

    pub async fn cleanup_expired_refresh_tokens(&self) -> Result<SqliteQueryResult, StoreError> {
        let now = Utc::now().naive_utc();
        let result = sqlx::query!(
            r#"
            DELETE FROM refresh_tokens
            WHERE expires_at < ?
            "#,
            now
        )
        .execute(&self.db_pool)
        .await?;
        Ok(result)
    }
}
