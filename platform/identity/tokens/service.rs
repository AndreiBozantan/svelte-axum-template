use chrono::NaiveDateTime;

use crate::common;

#[derive(Debug, Clone)]
pub struct CreateRefreshTokenCommand {
    pub jti: String,
    pub tenant_id: common::TenantId,
    pub user_id: common::UserId,
    pub token_hash: String,
    pub expires_at: NaiveDateTime,
}

#[derive(Debug, Clone)]
pub struct RefreshToken {
    pub user_id: common::UserId,
    pub token_hash: String,
    pub revoked_at: Option<NaiveDateTime>,
}

pub trait TRepository: Send + Sync {
    fn create(
        &self,
        db: &common::SqlContext,
        command: CreateRefreshTokenCommand,
    ) -> impl std::future::Future<Output = Result<(), common::RepoError>> + Send;

    fn revoke_by_jti(
        &self,
        db: &common::SqlContext,
        jti: &str,
    ) -> impl std::future::Future<Output = Result<(), common::RepoError>> + Send;

    fn find_by_jti(
        &self,
        db: &common::SqlContext,
        tenant_id: common::TenantId,
        jti: &str,
    ) -> impl std::future::Future<Output = Result<RefreshToken, common::RepoError>> + Send;

    fn revoke_all_for_user(
        &self,
        db: &common::SqlContext,
        tenant_id: common::TenantId,
        user_id: common::UserId,
    ) -> impl std::future::Future<Output = Result<(), common::RepoError>> + Send;
}
