use chrono::NaiveDateTime;
use sqlx::FromRow;

use crate::common::RepoError;
use crate::common::SqlContext;
use crate::constants;
use crate::identity::users;

#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "TEXT", rename_all = "lowercase")]
enum UserStatusRow {
    Onboarding,
    Active,
    Suspended,
    Archived,
}

/// Full `users` table projection. Some columns are only used for specific conversions
/// (e.g. auth lockout fields) or reserved for future API fields (names).
#[derive(Debug, Clone, FromRow)]
struct UserRow {
    id: i64,
    tenant_id: i64,
    #[allow(dead_code)]
    created_at: NaiveDateTime,
    #[allow(dead_code)]
    updated_at: NaiveDateTime,
    status: UserStatusRow,
    email: String,
    first_name: Option<String>,
    middle_name: Option<String>,
    last_name: Option<String>,
    password_hash: Option<String>,
    #[allow(dead_code)]
    sso_provider: Option<String>,
    #[allow(dead_code)]
    sso_id: Option<String>,
    failed_login_count: i64,
    last_failed_login: Option<NaiveDateTime>,
}

impl From<UserStatusRow> for users::UserStatus {
    fn from(value: UserStatusRow) -> Self {
        match value {
            UserStatusRow::Onboarding => Self::Onboarding,
            UserStatusRow::Active => Self::Active,
            UserStatusRow::Suspended => Self::Suspended,
            UserStatusRow::Archived => Self::Archived,
        }
    }
}

impl From<users::UserStatus> for UserStatusRow {
    fn from(value: users::UserStatus) -> Self {
        match value {
            users::UserStatus::Onboarding => Self::Onboarding,
            users::UserStatus::Active => Self::Active,
            users::UserStatus::Suspended => Self::Suspended,
            users::UserStatus::Archived => Self::Archived,
        }
    }
}

impl TryFrom<UserRow> for users::User {
    type Error = users::UserError;

    fn try_from(row: UserRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: users::UserId(row.id),
            tenant_id: users::TenantId(row.tenant_id),
            email: users::Email::parse(&row.email)?,
            status: row.status.into(),
            first_name: row.first_name,
            middle_name: row.middle_name,
            last_name: row.last_name,
        })
    }
}

impl TryFrom<UserRow> for users::UserAuthRecord {
    type Error = users::UserError;

    fn try_from(row: UserRow) -> Result<Self, Self::Error> {
        Ok(Self {
            user: row.clone().try_into()?,
            password_hash: row.password_hash,
            failed_login_count: row.failed_login_count,
            last_failed_login: row.last_failed_login,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Repository;

impl users::UserRepo for Repository {
    async fn create_user(&self, db: &SqlContext, command: users::CreateUserCommand) -> Result<users::User, RepoError> {
        let status: UserStatusRow = command.status.into();
        let email = command.email.as_str().to_string();
        let row = sqlx::query_as!(
            UserRow,
            r#"
            INSERT INTO users (tenant_id, status, email, password_hash, sso_provider, sso_id, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            RETURNING
                id as "id!",
                tenant_id as "tenant_id!",
                created_at as "created_at!",
                updated_at as "updated_at!",
                status as "status: UserStatusRow",
                email as "email!",
                first_name,
                middle_name,
                last_name,
                password_hash,
                sso_provider,
                sso_id,
                failed_login_count as "failed_login_count!",
                last_failed_login
            "#,
            command.tenant_id.0,
            status,
            email,
            command.password_hash,
            command.sso_provider,
            command.sso_id,
        )
        .fetch_one(db)
        .await?;
        row.try_into()
            .map_err(|_| RepoError::Database(sqlx::Error::RowNotFound))
    }

    async fn find_by_id(&self, db: &SqlContext, id: users::UserId) -> Result<users::User, RepoError> {
        let row = sqlx::query_as!(
            UserRow,
            r#"
            SELECT
                id as "id!",
                tenant_id as "tenant_id!",
                created_at as "created_at!",
                updated_at as "updated_at!",
                status as "status: UserStatusRow",
                email as "email!",
                first_name,
                middle_name,
                last_name,
                password_hash,
                sso_provider,
                sso_id,
                failed_login_count as "failed_login_count!",
                last_failed_login
            FROM users
            WHERE id = ?
            "#,
            id.0
        )
        .fetch_one(db)
        .await?;
        row.try_into()
            .map_err(|e: users::UserError| RepoError::RowConversionFailed(e.to_string()))
    }

    async fn find_auth_by_email(&self, db: &SqlContext, email: &users::Email) -> Result<Option<users::UserAuthRecord>, RepoError> {
        let email_str = email.as_str().to_string();
        let row = sqlx::query_as!(
            UserRow,
            r#"
            SELECT
                id as "id!",
                tenant_id as "tenant_id!",
                created_at as "created_at!",
                updated_at as "updated_at!",
                status as "status: UserStatusRow",
                email as "email!",
                first_name,
                middle_name,
                last_name,
                password_hash,
                sso_provider,
                sso_id,
                failed_login_count as "failed_login_count!",
                last_failed_login
            FROM users
            WHERE email = ?
            "#,
            email_str
        )
        .fetch_optional(db)
        .await?;

        row.map(TryInto::try_into)
            .transpose()
            .map_err(|_| RepoError::Database(sqlx::Error::RowNotFound))
    }

    async fn list_by_tenant(&self, db: &SqlContext, query: users::ListUsersQuery) -> Result<users::UserList, RepoError> {
        let rows = sqlx::query_as!(
            UserRow,
            r#"
            SELECT
                id as "id!",
                tenant_id as "tenant_id!",
                created_at as "created_at!",
                updated_at as "updated_at!",
                status as "status: UserStatusRow",
                email as "email!",
                first_name,
                middle_name,
                last_name,
                password_hash,
                sso_provider,
                sso_id,
                failed_login_count as "failed_login_count!",
                last_failed_login
            FROM users
            WHERE tenant_id = ?
            ORDER BY id ASC
            LIMIT ? OFFSET ?
            "#,
            query.tenant_id.0,
            query.limit,
            query.offset
        )
        .fetch_all(db)
        .await?;

        let total_row = sqlx::query!(
            "SELECT COUNT(*) as count FROM users WHERE tenant_id = ?",
            query.tenant_id.0
        )
        .fetch_one(db)
        .await?;

        let users = rows
            .into_iter()
            .map(users::User::try_from)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| RepoError::Database(sqlx::Error::RowNotFound))?;

        Ok(users::UserList {
            users,
            total: total_row.count,
        })
    }

    async fn link_sso_user(&self, db: &SqlContext, command: users::LinkSsoUserCommand) -> Result<users::User, RepoError> {
        let email = command.email.as_str().to_string();
        let row = sqlx::query_as!(
            UserRow,
            r#"
            INSERT INTO users (tenant_id, status, email, sso_provider, sso_id, created_at, updated_at)
            VALUES (?, 'active', ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            ON CONFLICT (email) DO UPDATE SET
                sso_provider = excluded.sso_provider,
                sso_id = excluded.sso_id,
                updated_at = CURRENT_TIMESTAMP
            RETURNING
                id as "id!",
                tenant_id as "tenant_id!",
                created_at as "created_at!",
                updated_at as "updated_at!",
                status as "status: UserStatusRow",
                email as "email!",
                first_name,
                middle_name,
                last_name,
                password_hash,
                sso_provider,
                sso_id,
                failed_login_count as "failed_login_count!",
                last_failed_login
            "#,
            command.tenant_id.0,
            email,
            command.sso_provider,
            command.sso_id
        )
        .fetch_one(db)
        .await?;
        row.try_into()
            .map_err(|_| RepoError::Database(sqlx::Error::RowNotFound))
    }

    async fn update_admin_credentials(
        &self,
        db: &SqlContext,
        command: users::UpdateAdminCredentialsCommand,
    ) -> Result<(), RepoError> {
        let email = command.email.as_str().to_string();
        let result = sqlx::query!(
            r#"
            UPDATE users
            SET email = ?, password_hash = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            "#,
            email,
            command.password_hash,
            command.user_id.0
        )
        .execute(db)
        .await?;

        if result.rows_affected() == 0 {
            return Err(RepoError::NotFound);
        }
        Ok(())
    }

    async fn increment_failed_login(&self, db: &SqlContext, user_id: users::UserId) -> Result<(), RepoError> {
        let window_length = format!("-{} minutes", constants::auth::FAILED_LOGIN_WINDOW_MINUTES);
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
            user_id.0
        )
        .execute(db)
        .await?;
        Ok(())
    }

    async fn reset_failed_login(&self, db: &SqlContext, user_id: users::UserId) -> Result<(), RepoError> {
        sqlx::query!(
            r#"
            UPDATE users SET
                failed_login_count = 0,
                last_failed_login = NULL
            WHERE id = ?
            "#,
            user_id.0
        )
        .execute(db)
        .await?;
        Ok(())
    }
}
