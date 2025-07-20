use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

use crate::app::{DbError, DbPoolType};

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub password_hash: Option<String>, // Nullable for SSO users
    pub email: Option<String>,
    pub tenant_id: Option<i64>,
    pub sso_provider: Option<String>,
    pub sso_id: Option<String>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NewUser {
    pub username: String,
    pub password_hash: Option<String>, // Nullable for SSO users
    pub email: Option<String>,
    pub tenant_id: Option<i64>,
    pub sso_provider: Option<String>,
    pub sso_id: Option<String>,
}

pub struct Users {
    db: DbPoolType
}

impl Users {
    pub fn new(db: DbPoolType) -> Self {
        Self { db }
    }

    pub async fn create(&self, new_user: NewUser) -> Result<User, DbError> {
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
        .await
        .map_err(|e| DbError::OperationFailed(e))?;

        return Ok(user);
    }

    pub async fn get_by_id(&self, id: i64) -> Result<User, DbError> {
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
            sqlx::Error::RowNotFound => DbError::UserNotFound,
            _ => DbError::OperationFailed(e),
        })?;

        return Ok(user);
    }

    pub async fn get_by_name(&self, username: &str) -> Result<User, DbError> {
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
            sqlx::Error::RowNotFound => DbError::UserNotFound,
            _ => DbError::OperationFailed(e),
        })?;
        return Ok(user);
    }

    pub async fn get_by_sso_id(&self, sso_provider: &str, sso_id: &str) -> Result<User, DbError> {
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
            sqlx::Error::RowNotFound => DbError::UserNotFound,
            _ => DbError::OperationFailed(e),
        })?;
        return Ok(user);
    }
}