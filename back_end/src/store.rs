use anyhow::Result;
use sqlx::sqlite::SqliteQueryResult;
use thiserror::Error;

use crate::db::{DbPoolRef, schema::{ApiToken, User, NewUser}};

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
}

#[derive(Clone, Debug)]
pub struct Store {
    db_pool: DbPoolRef,
    default_api_token: String,
}

impl Store {
    pub fn new(api_token: &str, db_pool: DbPoolRef) -> Self {
        Self {
            db_pool,
            default_api_token: api_token.to_string(),
        }
    }

    pub fn api_token_check(&self, auth_header: &str) -> bool {
        // For backward compatibility, also check against the default token
        if auth_header == format!("Bearer {}", self.default_api_token) {
            return true;
        }

        // Extract token from the authorization header
        if let Some(token) = auth_header.strip_prefix("Bearer ") {
            // Try to verify the token synchronously
            // For the sync API, we'll just use the default token for now
            // A more sophisticated implementation could cache tokens or use a blocking operation
            return token == self.default_api_token;
        }

        return false;
    }

    // Database methods

    // User operations
    pub async fn create_user(&self, new_user: NewUser) -> Result<User, StoreError> {
        let user = sqlx::query_as!(
            User,
            r#"
            INSERT INTO users (username, password_hash, email, created_at, updated_at)
            VALUES (?, ?, ?, strftime('%s', 'now'), strftime('%s', 'now'))
            RETURNING id, username, password_hash, email, created_at, updated_at
            "#,
            new_user.username,
            new_user.password_hash,
            new_user.email
        )
        .fetch_one(&*self.db_pool)
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
                password_hash "password_hash!",
                email,
                created_at "created_at!",
                updated_at "updated_at!"
            FROM users
            WHERE id = ?
            "#,
            id
        )
        .fetch_one(&*self.db_pool)
        .await
        .map_err(|e| {
            if let sqlx::Error::RowNotFound = e {
                StoreError::UserNotFound
            } else {
                StoreError::Database(e)
            }
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
                password_hash "password_hash!",
                email,
                created_at "created_at!",
                updated_at "updated_at!"
            FROM users
            WHERE username = ?
            "#,
            username
        )
        .fetch_one(&*self.db_pool)
        .await
        .map_err(|e| {
            if let sqlx::Error::RowNotFound = e {
                StoreError::UserNotFound
            } else {
                StoreError::Database(e)
            }
        })?;

        return Ok(user);
    }

    // Token operations
    pub async fn create_token(&self, user_id: i64, token: &str, expires_at: Option<i64>) -> Result<ApiToken, StoreError> {
        let token = sqlx::query_as!(
            ApiToken,
            r#"
            INSERT INTO api_tokens (token, user_id, created_at, expires_at)
            VALUES (?, ?, strftime('%s', 'now'), ?)
            RETURNING
                id "id!",
                token "token!",
                user_id "user_id!",
                created_at "created_at!",
                expires_at
            "#,
            token,
            user_id,
            expires_at
        )
        .fetch_one(&*self.db_pool)
        .await?;

        return Ok(token);
    }

    pub async fn get_token(&self, token: &str) -> Result<ApiToken, StoreError> {
        let token = sqlx::query_as!(
            ApiToken,
            r#"
            SELECT
                id as "id!",
                token as "token!",
                user_id as "user_id!",
                created_at as "created_at!",
                expires_at
            FROM api_tokens
            WHERE token = ?"#,
            token
        )
        .fetch_one(&*self.db_pool)
        .await
        .map_err(|e| {
            if let sqlx::Error::RowNotFound = e {
                StoreError::TokenNotFound
            } else {
                StoreError::Database(e)
            }
        })?;

        return Ok(token);
    }

    pub async fn delete_token(&self, token: &str) -> Result<SqliteQueryResult, StoreError> {
        let result = sqlx::query!(
            r#"
            DELETE FROM api_tokens
            WHERE token = ?
            "#,
            token
        )
        .execute(&*self.db_pool)
        .await?;

        return Ok(result);
    }

    pub async fn verify_token(&self, token: &str) -> Result<bool, StoreError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let result = sqlx::query!(
            r#"
            SELECT COUNT(*) as count
            FROM api_tokens
            WHERE token = ?
              AND (expires_at IS NULL OR expires_at > ?)
            "#,
            token,
            now
        )
        .fetch_one(&*self.db_pool)
        .await?;

        return Ok(result.count > 0);
    }

    // For future: add methods for updating user info, listing users, etc.
}
