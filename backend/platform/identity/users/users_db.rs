use chrono::NaiveDateTime;
use sqlx::FromRow;

use crate::platform::common;
use crate::platform::db;
use crate::platform::identity::users;

#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "TEXT", rename_all = "lowercase")]
enum Status {
    Onboarding,
    Active,
    Suspended,
    Archived,
}

/// Full `users` table projection. Some columns are only used for specific conversions
/// (e.g. auth lockout fields) or reserved for future API fields (names).
#[derive(Debug, Clone, FromRow)]
#[allow(dead_code)]
struct Row {
    id: i64,
    tenant_id: i64,
    created_at: NaiveDateTime,
    updated_at: NaiveDateTime,
    status: Status,
    email: String,
    first_name: Option<String>,
    middle_name: Option<String>,
    last_name: Option<String>,
    password_hash: Option<String>,
    sso_provider: Option<String>,
    sso_id: Option<String>,
    failed_login_count: i64,
    last_failed_login: Option<NaiveDateTime>,
}

impl From<Status> for users::UserStatus {
    fn from(value: Status) -> Self {
        match value {
            Status::Onboarding => Self::Onboarding,
            Status::Active => Self::Active,
            Status::Suspended => Self::Suspended,
            Status::Archived => Self::Archived,
        }
    }
}

impl From<users::UserStatus> for Status {
    fn from(value: users::UserStatus) -> Self {
        match value {
            users::UserStatus::Onboarding => Self::Onboarding,
            users::UserStatus::Active => Self::Active,
            users::UserStatus::Suspended => Self::Suspended,
            users::UserStatus::Archived => Self::Archived,
        }
    }
}

impl TryFrom<Row> for users::User {
    type Error = db::Error;
    fn try_from(row: Row) -> Result<Self, Self::Error> {
        Ok(Self {
            id: common::UserId(row.id),
            tenant_id: common::TenantId(row.tenant_id),
            email: common::Email::parse(&row.email)
                .ok_or_else(|| db::Error::RowConversionFailed("invalid email".to_string()))?,
            status: row.status.into(),
            first_name: row.first_name,
            middle_name: row.middle_name,
            last_name: row.last_name,
        })
    }
}

impl TryFrom<Row> for users::UserAuthRecord {
    type Error = db::Error;
    fn try_from(row: Row) -> Result<Self, Self::Error> {
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

impl users::TRepository for Repository {
    async fn create_user(
        &self,
        db: &db::Context,
        command: users::CreateUserCommand,
    ) -> Result<users::User, db::Error> {
        let status: Status = command.status.into();
        let email = command.email.as_str().to_string();
        let row = sqlx::query_as!(
            Row,
            r#"
            INSERT INTO users (tenant_id, status, email, password_hash, sso_provider, sso_id, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            RETURNING
                id as "id!",
                tenant_id as "tenant_id!",
                created_at as "created_at!",
                updated_at as "updated_at!",
                status as "status: Status",
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
    }

    async fn find_by_id(
        &self,
        db: &db::Context,
        tenant_id: common::TenantId,
        id: common::UserId,
    ) -> Result<users::User, db::Error> {
        let row = sqlx::query_as!(
            Row,
            r#"
            SELECT
                id as "id!",
                tenant_id as "tenant_id!",
                created_at as "created_at!",
                updated_at as "updated_at!",
                status as "status: Status",
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
            AND tenant_id = ?
            "#,
            id.0,
            tenant_id.0,
        )
        .fetch_one(db)
        .await?;
        row.try_into()
    }

    async fn find_sso_info_by_id(
        &self,
        db: &db::Context,
        id: common::UserId,
    ) -> Result<users::UserSsoInfo, db::Error> {
        let record = sqlx::query!(
            r#"
            SELECT sso_provider, sso_id FROM users
            WHERE id = ?
            "#,
            id.0
        )
        .fetch_one(db)
        .await?;

        Ok(users::UserSsoInfo {
            sso_provider: record.sso_provider,
            sso_id: record.sso_id,
        })
    }

    async fn find_auth_details_by_email(
        &self,
        db: &db::Context,
        email: &common::Email,
    ) -> Result<Option<users::UserAuthRecord>, db::Error> {
        let email_str = email.as_str().to_string();
        let row = sqlx::query_as!(
            Row,
            r#"
            SELECT
                id as "id!",
                tenant_id as "tenant_id!",
                created_at as "created_at!",
                updated_at as "updated_at!",
                status as "status: Status",
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
        row.map(TryInto::try_into).transpose()
    }

    async fn list_by_tenant(
        &self,
        db: &db::Context,
        query: users::ListUsersQuery,
    ) -> Result<users::UserList, db::Error> {
        let rows = sqlx::query_as!(
            Row,
            r#"
            SELECT
                id as "id!",
                tenant_id as "tenant_id!",
                created_at as "created_at!",
                updated_at as "updated_at!",
                status as "status: Status",
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
            .collect::<Result<Vec<_>, _>>()?;

        Ok(users::UserList {
            users,
            total: total_row.count,
        })
    }

    async fn link_sso_user(
        &self,
        db: &db::Context,
        command: users::LinkSsoUserCommand,
    ) -> Result<users::User, db::Error> {
        let email = command.email.as_str().to_string();
        let row = sqlx::query_as!(
            Row,
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
                status as "status: Status",
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
    }

    async fn update_admin_credentials(
        &self,
        db: &db::Context,
        command: users::UpdateAdminCredentialsCommand,
    ) -> Result<(), db::Error> {
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
            return Err(db::Error::RowNotFound);
        }
        Ok(())
    }

    async fn update_password_hash(
        &self,
        db: &db::Context,
        tenant_id: common::TenantId,
        user_id: common::UserId,
        password_hash: &str,
    ) -> Result<(), db::Error> {
        let result = sqlx::query!(
            r#"
            UPDATE users
            SET password_hash = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND tenant_id = ?
            "#,
            password_hash,
            user_id.0,
            tenant_id.0,
        )
        .execute(db)
        .await?;

        if result.rows_affected() == 0 {
            return Err(db::Error::RowNotFound);
        }
        Ok(())
    }

    async fn update_failed_login_count(
        &self,
        db: &db::Context,
        tenant_id: common::TenantId,
        user_id: common::UserId,
        count: i64,
    ) -> Result<(), db::Error> {
        let result = sqlx::query!(
            r#"
            UPDATE users SET
                failed_login_count = ?,
                last_failed_login = CURRENT_TIMESTAMP
            WHERE id = ? AND tenant_id = ?
            "#,
            count,
            user_id.0,
            tenant_id.0,
        )
        .execute(db)
        .await?;

        if result.rows_affected() == 0 {
            return Err(db::Error::RowNotFound);
        }
        Ok(())
    }

    async fn reset_failed_login_count(
        &self,
        db: &db::Context,
        tenant_id: common::TenantId,
        user_id: common::UserId,
    ) -> Result<(), db::Error> {
        let result = sqlx::query!(
            r#"
            UPDATE users SET
                failed_login_count = 0,
                last_failed_login = NULL
            WHERE id = ? AND tenant_id = ?
            "#,
            user_id.0,
            tenant_id.0,
        )
        .execute(db)
        .await?;

        if result.rows_affected() == 0 {
            return Err(db::Error::RowNotFound);
        }
        Ok(())
    }
}
