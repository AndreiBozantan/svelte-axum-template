use chrono::NaiveDateTime;
use thiserror::Error;

use crate::platform::common;
use crate::platform::db;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserStatus {
    Onboarding,
    Active,
    Suspended,
    Archived,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct User {
    pub id: common::UserId,
    pub tenant_id: common::TenantId,
    pub email: common::Email,
    pub status: UserStatus,
    pub first_name: Option<String>,
    pub middle_name: Option<String>,
    pub last_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UserAuthRecord {
    pub user: User,
    pub password_hash: Option<String>,
    pub failed_login_count: i64,
    pub last_failed_login: Option<NaiveDateTime>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct CreateUserCommand {
    pub tenant_id: common::TenantId,
    pub status: UserStatus,
    pub email: common::Email,
    pub first_name: Option<String>,
    pub middle_name: Option<String>,
    pub last_name: Option<String>,
    pub password_hash: Option<String>,
    pub sso_provider: Option<String>,
    pub sso_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct LinkSsoUserCommand {
    pub email: common::Email,
    pub tenant_id: common::TenantId,
    pub sso_provider: String,
    pub sso_id: String,
}

#[derive(Debug, Clone)]
pub struct UpdateAdminCredentialsCommand {
    pub user_id: common::UserId,
    pub email: common::Email,
    pub password_hash: String,
}

#[derive(Debug, Clone)]
pub struct ListUsersQuery {
    pub tenant_id: common::TenantId,
    pub limit: i64,
    pub offset: i64,
}

#[derive(Debug, Clone)]
pub struct UserList {
    pub users: Vec<User>,
    pub total: i64,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct UserSsoInfo {
    pub sso_provider: Option<String>,
    pub sso_id: Option<String>,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("user not found")]
    NotFound,

    #[error("user already exists")]
    AlreadyExists,

    #[error("database error: {0}")]
    DatabaseOperationFailed(db::Error),
}

impl From<db::Error> for Error {
    fn from(error: db::Error) -> Self {
        match error {
            db::Error::RowNotFound => Self::NotFound,
            db::Error::UniqueConstraintViolation(_) => Self::AlreadyExists,
            other => Self::DatabaseOperationFailed(other),
        }
    }
}

#[derive(Clone)]
pub struct Service {
    pub context: common::ArcContext,
    pub users: super::db::Repository,
}

impl Service {
    #[must_use]
    pub const fn new(
        repo: super::db::Repository,
        context: common::ArcContext,
    ) -> Self {
        Self { users: repo, context }
    }
}
