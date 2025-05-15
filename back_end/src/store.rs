use sqlx::sqlite::SqliteQueryResult;
use thiserror::Error;

use crate::db::DbPoolRef;
use crate::db::schema::{ApiToken, NewTenant, NewUser, Tenant, User, current_timestamp};
use crate::auth_utils::{JwtConfig, validate_jwt};

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
    db_pool: DbPoolRef,
    default_api_token: String,
    pub jwt_config: JwtConfig,
}

impl Store {
    pub fn new(api_token: &str, db_pool: DbPoolRef) -> Self {
        Self {
            db_pool,
            default_api_token: api_token.to_string(),
            jwt_config: JwtConfig::default(),
        }
    }
    
    pub fn new_with_jwt(api_token: &str, db_pool: DbPoolRef, jwt_config: &crate::appconfig::JwtConfig) -> Self {
        Self {
            db_pool,
            default_api_token: api_token.to_string(),
            jwt_config: JwtConfig {
                secret: jwt_config.secret.clone(),
                access_token_expiry_mins: jwt_config.access_token_expiry_mins,
                refresh_token_expiry_mins: jwt_config.refresh_token_expiry_mins,
            },
        }
    }pub async fn api_token_check_async(&self, auth_header: &str) -> Result<bool, StoreError> {
        // Extract token from the authorization header
        if let Some(token) = auth_header.strip_prefix("Bearer ") {                // Attempt to validate the JWT token
            match validate_jwt(token, &self.jwt_config) {
                Ok(_claims) => {
                    // Check if token is in database and not expired
                    let result = self.verify_token(token).await?;
                    Ok(result)
                }
                Err(_) => {
                    // Fallback to the legacy token verification (for backward compatibility)
                    let old_token_valid = token == self.default_api_token;
                    Ok(old_token_valid)
                }
            }
        } else {
            Ok(false)
        }
    }

    pub fn api_token_check(&self, auth_header: &str) -> bool {
        // Extract token from the authorization header
        if let Some(token) = auth_header.strip_prefix("Bearer ") {
            // For the sync API, we'll just use the default token for now
            // A more sophisticated implementation should use the async version
            return token == self.default_api_token;
        }

        false
    }

    // Database methods

    // User operations
    pub async fn create_user(&self, new_user: NewUser) -> Result<User, StoreError> {
        let user = sqlx::query_as!(
            User,
            r#"
            INSERT INTO users (username, password_hash, email, tenant_id, created_at, updated_at)
            VALUES (?, ?, ?, ?, strftime('%s', 'now'), strftime('%s', 'now'))
            RETURNING id, username, password_hash, email, tenant_id, created_at, updated_at
            "#,
            new_user.username,
            new_user.password_hash,
            new_user.email,
            new_user.tenant_id
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
                tenant_id "tenant_id!",
                created_at "created_at!",
                updated_at "updated_at!"
            FROM users
            WHERE id = ?
            "#,
            id
        )
        .fetch_one(&*self.db_pool)
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
                password_hash "password_hash!",
                email,
                tenant_id "tenant_id!",
                created_at "created_at!",
                updated_at "updated_at!"
            FROM users
            WHERE username = ?
            "#,
            username
        )
        .fetch_one(&*self.db_pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => StoreError::UserNotFound,
            _ => StoreError::Database(e),
        })?;

        return Ok(user);
    }

    pub async fn update_user(&self, id: i64, user: User) -> Result<User, StoreError> {
        let updated_user = sqlx::query_as!(
            User,
            r#"
            UPDATE users
            SET username = ?,
                password_hash = ?,
                email = ?,
                tenant_id = ?,
                updated_at = strftime('%s', 'now')
            WHERE id = ?
            RETURNING id, username, password_hash, email, tenant_id, created_at, updated_at
            "#,
            user.username,
            user.password_hash,
            user.email,
            user.tenant_id,
            id
        )
        .fetch_one(&*self.db_pool)
        .await?;

        Ok(updated_user)
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
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => StoreError::TokenNotFound,
            _ => StoreError::Database(e),
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
    }    pub async fn verify_token(&self, token: &str) -> Result<bool, StoreError> {
        let now = current_timestamp();

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

        Ok(result.count > 0)
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
        .fetch_all(&*self.db_pool)
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
        .fetch_one(&*self.db_pool)
        .await?;

        return Ok(tenant)
    }

    pub async fn create_tenant(&self, tenant: NewTenant) -> Result<Tenant, StoreError> {
        let now = current_timestamp();

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
        .fetch_one(&*self.db_pool)
        .await?;

        return Ok(tenant)
    }

    pub async fn update_tenant(&self, id: i64, tenant: NewTenant) -> Result<Tenant, StoreError> {
        let now = current_timestamp();

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
        .fetch_one(&*self.db_pool)
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
        .execute(&*self.db_pool)
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
                password_hash as "password_hash!",
                email,
                tenant_id as "tenant_id!",
                created_at as "created_at!",
                updated_at as "updated_at!"
            FROM users
            WHERE tenant_id = ?
            "#,
            tenant_id
        )
        .fetch_all(&*self.db_pool)
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
        .execute(&*self.db_pool)
        .await?;

        return Ok(result)
    }
}
