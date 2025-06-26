use std::path::Path;
use std::str::FromStr;
use chrono::Utc;
use thiserror::Error;
use sqlx::sqlite::{SqliteQueryResult, SqliteConnectOptions, SqlitePoolOptions};

use crate::app;
use crate::db;
use crate::db::schema::{NewUser, NewRefreshToken, RefreshToken, Tenant, User};

// TODO: split the store module in separate files for each table

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("Database connection error: {0}")]
    Connection(sqlx::Error),

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Database migration error: {0}")]
    Migration(#[from] db::migrations::MigrationError),

    #[error("User not found")]
    UserNotFound,

    #[error("Token not found")]
    TokenNotFound,

    #[error("Tenant not found")]
    TenantNotFound,
}

#[derive(Clone, Debug)]
pub struct Store {
    db: sqlx::SqlitePool
}

impl Store {
    pub fn db(&self) -> &sqlx::SqlitePool {
        &self.db
    }

    pub async fn new(db_config: &app::DatabaseConfig) -> Result<Self, StoreError> {
        let options = SqliteConnectOptions::from_str(&db_config.url)?
                .create_if_missing(true)
                .foreign_keys(true)
                // Increase SQLite busy timeout to handle concurrent connections better
                .busy_timeout(std::time::Duration::from_secs(30));

        let pool = SqlitePoolOptions::new()
            .max_connections(db_config.max_connections)
            .connect_with(options)
            .await
            .map_err(|e| StoreError::Connection(e))?;
        let store = Self { db: pool };

        // Run migrations if run_db_migrations_on_startup is enabled
        if !db_config.run_db_migrations_on_startup {
            tracing::info!("Database migrations skipped (run_db_migrations_on_startup  = false)");
        } else {
            // if there is a backend directory in the current working directory, use that as the migrations path
            let migrations_path = match Path::new("backend").exists() {
                true => Path::new("backend/migrations"),
                false => Path::new("migrations")
            };

            // Run migrations using our migrations module
            db::migrations::run(&store, migrations_path).await?;
            tracing::info!("Database migrations completed successfully");
        }

        tracing::info!("Database initialized successfully");
        Ok(store)
    }

    pub async fn create_user(&self, new_user: NewUser) -> Result<User, StoreError> {
        let user = sqlx::query_as!(
            User,
            r#"
            INSERT INTO users (username, password_hash, email, tenant_id, sso_provider, sso_id, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            RETURNING id, username, password_hash, email, tenant_id, sso_provider, sso_id, created_at, updated_at
            "#,
            new_user.username,
            new_user.password_hash,
            new_user.email,
            new_user.tenant_id,
            new_user.sso_provider,
            new_user.sso_id)
        .fetch_one(&self.db)
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
        .fetch_one(&self.db)
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
        .fetch_one(&self.db)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => StoreError::UserNotFound,
            _ => StoreError::Database(e),
        })?;
        return Ok(user);
    }

    pub async fn store_refresh_token(&self, new_refresh_token: NewRefreshToken) -> Result<(), StoreError> {
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
        .execute(&self.db)
        .await?;
        Ok(())
    }

    pub async fn revoke_refresh_token(&self, jti: &str) -> Result<(), StoreError> {
        sqlx::query!(
            r#"
            UPDATE refresh_tokens
            SET revoked_at = CURRENT_TIMESTAMP
            WHERE jti = ?
            "#,
            jti
        )
        .execute(&self.db)
        .await?;
        Ok(())
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
        .fetch_one(&self.db)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => StoreError::TenantNotFound,
            _ => StoreError::Database(e),
        })?;
        return Ok(tenant)
    }

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
        .fetch_one(&self.db)
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
        .execute(&self.db)
        .await?;
        Ok(result)
    }

    /// Cleanup expired refresh tokens
    /// TODO: add a way to use this (e.g. scheduled task)
    pub async fn _cleanup_expired_refresh_tokens(&self) -> Result<SqliteQueryResult, StoreError> {
        let now = Utc::now().naive_utc();
        let result = sqlx::query!(
            r#"
            DELETE FROM refresh_tokens
            WHERE expires_at < ?
            "#,
            now
        )
        .execute(&self.db)
        .await?;
        Ok(result)
    }

    pub async fn get_user_by_sso_id(&self, sso_provider: &str, sso_id: &str) -> Result<User, StoreError> {
        let user = sqlx::query_as::<_, User>(
            r#"
            SELECT
                id,
                username,
                password_hash,
                email,
                tenant_id,
                sso_provider,
                sso_id,
                created_at,
                updated_at
            FROM users
            WHERE sso_provider = ? AND sso_id = ?
            "#
        )
        .bind(sso_provider)
        .bind(sso_id)
        .fetch_one(&self.db)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => StoreError::UserNotFound,
            _ => StoreError::Database(e),
        })?;
        return Ok(user);
    }
}
