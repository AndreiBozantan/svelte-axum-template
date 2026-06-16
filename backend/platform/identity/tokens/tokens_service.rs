use chrono::NaiveDateTime;

use crate::platform::common;
use crate::platform::db;

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
        db: &db::Context,
        command: CreateRefreshTokenCommand,
    ) -> impl std::future::Future<Output = Result<(), db::Error>> + Send;

    fn revoke_by_jti(
        &self,
        db: &db::Context,
        tenant_id: common::TenantId,
        jti: &str,
    ) -> impl std::future::Future<Output = Result<(), db::Error>> + Send;

    fn find_by_jti(
        &self,
        db: &db::Context,
        tenant_id: common::TenantId,
        jti: &str,
    ) -> impl std::future::Future<Output = Result<RefreshToken, db::Error>> + Send;

    fn revoke_all_for_user(
        &self,
        db: &db::Context,
        tenant_id: common::TenantId,
        user_id: common::UserId,
    ) -> impl std::future::Future<Output = Result<(), db::Error>> + Send;
}
