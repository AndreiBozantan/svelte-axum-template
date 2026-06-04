use chrono::NaiveDateTime;
use thiserror::Error;

use crate::common::RepoError;
use crate::common::SqlContext;



#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UserId(pub i64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TenantId(pub i64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Email(String);

impl Email {
    pub fn parse(raw: &str) -> Result<Self, UserError> {
        let normalized = raw.trim().to_ascii_lowercase();
        if normalized.is_empty() || !normalized.contains('@') {
            return Err(UserError::InvalidEmail);
        }
        Ok(Self(normalized))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserStatus {
    Onboarding,
    Active,
    Suspended,
    Archived,
}

#[derive(Debug, Clone)]
pub struct User {
    pub id: UserId,
    pub tenant_id: TenantId,
    pub email: Email,
    #[allow(dead_code)]
    pub status: UserStatus,
    #[allow(dead_code)]
    pub first_name: Option<String>,
    #[allow(dead_code)]
    pub middle_name: Option<String>,
    #[allow(dead_code)]
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
pub struct CreateUserCommand {
    pub tenant_id: TenantId,
    pub status: UserStatus,
    pub email: Email,
    #[allow(dead_code)]
    pub first_name: Option<String>,
    #[allow(dead_code)]
    pub middle_name: Option<String>,
    #[allow(dead_code)]
    pub last_name: Option<String>,
    pub password_hash: Option<String>,
    pub sso_provider: Option<String>,
    pub sso_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct LinkSsoUserCommand {
    pub email: Email,
    pub tenant_id: TenantId,
    pub sso_provider: String,
    pub sso_id: String,
}

#[derive(Debug, Clone)]
pub struct UpdateAdminCredentialsCommand {
    pub user_id: UserId,
    pub email: Email,
    pub password_hash: String,
}

#[derive(Debug, Clone)]
pub struct ListUsersQuery {
    pub tenant_id: TenantId,
    pub limit: i64,
    pub offset: i64,
}

#[derive(Debug, Clone)]
pub struct UserList {
    pub users: Vec<User>,
    pub total: i64,
}

#[derive(Debug, Error)]
pub enum UserError {
    #[error("invalid email address")]
    InvalidEmail,

    #[error("user not found")]
    NotFound,

    #[error("user already exists")]
    AlreadyExists,

    #[error("database error: {0}")]
    Database(RepoError),
}

impl From<RepoError> for UserError {
    fn from(error: RepoError) -> Self {
        match error {
            RepoError::NotFound => Self::NotFound,
            RepoError::UniqueViolation(_) => Self::AlreadyExists,
            other => Self::Database(other),
        }
    }
}

pub trait UserRepo: Send + Sync {
    fn create_user(
        &self,
        db: &SqlContext,
        command: CreateUserCommand,
    ) -> impl std::future::Future<Output = Result<User, RepoError>> + Send;

    fn find_by_id(
        &self,
        db: &SqlContext,
        id: UserId,
    ) -> impl std::future::Future<Output = Result<User, RepoError>> + Send;

    fn find_auth_by_email(
        &self,
        db: &SqlContext,
        email: &Email,
    ) -> impl std::future::Future<Output = Result<Option<UserAuthRecord>, RepoError>> + Send;

    fn list_by_tenant(
        &self,
        db: &SqlContext,
        query: ListUsersQuery,
    ) -> impl std::future::Future<Output = Result<UserList, RepoError>> + Send;

    fn link_sso_user(
        &self,
        db: &SqlContext,
        command: LinkSsoUserCommand,
    ) -> impl std::future::Future<Output = Result<User, RepoError>> + Send;

    fn update_admin_credentials(
        &self,
        db: &SqlContext,
        command: UpdateAdminCredentialsCommand,
    ) -> impl std::future::Future<Output = Result<(), RepoError>> + Send;

    fn increment_failed_login(
        &self,
        db: &SqlContext,
        user_id: UserId,
    ) -> impl std::future::Future<Output = Result<(), RepoError>> + Send;

    fn reset_failed_login(
        &self,
        db: &SqlContext,
        user_id: UserId,
    ) -> impl std::future::Future<Output = Result<(), RepoError>> + Send;
}

#[derive(Clone)]
pub struct UserService<R: UserRepo> {
    repo: R,
}

impl<R: UserRepo> UserService<R> {
    #[must_use]
    pub const fn new(repo: R) -> Self {
        Self { repo }
    }

    #[allow(dead_code)]
    pub async fn create_user(&self, db: &SqlContext, command: CreateUserCommand) -> Result<User, UserError> {
        self.repo.create_user(db, command).await.map_err(Into::into)
    }

    pub async fn get_user(&self, db: &SqlContext, id: UserId) -> Result<User, UserError> {
        self.repo.find_by_id(db, id).await.map_err(Into::into)
    }

    pub async fn get_user_for_auth(&self, db: &SqlContext, email: &Email) -> Result<Option<UserAuthRecord>, UserError> {
        self.repo.find_auth_by_email(db, email).await.map_err(Into::into)
    }

    pub async fn list_users(&self, db: &SqlContext, query: ListUsersQuery) -> Result<UserList, UserError> {
        self.repo.list_by_tenant(db, query).await.map_err(Into::into)
    }

    pub async fn link_sso_user(&self, db: &SqlContext, command: LinkSsoUserCommand) -> Result<User, UserError> {
        self.repo.link_sso_user(db, command).await.map_err(Into::into)
    }

    pub async fn update_admin_credentials(
        &self,
        db: &SqlContext,
        command: UpdateAdminCredentialsCommand,
    ) -> Result<(), UserError> {
        self.repo
            .update_admin_credentials(db, command)
            .await
            .map_err(Into::into)
    }

    pub async fn record_failed_login(&self, db: &SqlContext, user_id: UserId) -> Result<(), UserError> {
        self.repo.increment_failed_login(db, user_id).await.map_err(Into::into)
    }

    pub async fn reset_failed_login(&self, db: &SqlContext, user_id: UserId) -> Result<(), UserError> {
        self.repo.reset_failed_login(db, user_id).await.map_err(Into::into)
    }
}
