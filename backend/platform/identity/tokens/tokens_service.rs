use chrono::NaiveDateTime;

use crate::platform::common;

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
