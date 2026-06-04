use chrono::NaiveDateTime;
use thiserror::Error;

use crate::common::ArcContext;
use crate::common::RepoError;
use crate::common::SqlContext;
use crate::constants;
use crate::identity::users;
use crate::jwt;

use crate::internal::tokens;

use super::util::{self, DUMMY_HASH};

#[derive(Debug, Clone)]
pub struct LoginCommand {
    pub email: users::service::Email,
    pub password: String,
}

#[derive(Debug, Clone)]
pub struct CreateRefreshTokenCommand {
    pub jti: String,
    pub tenant_id: users::service::TenantId,
    pub user_id: users::service::UserId,
    pub token_hash: String,
    pub expires_at: NaiveDateTime,
}

#[derive(Debug, Clone)]
pub struct RefreshToken {
    pub user_id: users::service::UserId,
    pub token_hash: String,
    pub revoked_at: Option<NaiveDateTime>,
}

#[derive(Debug, Clone)]
pub struct AuthSession {
    pub user: users::service::User,
    pub access_token: jwt::TokenWithClaims,
    pub refresh_token: jwt::TokenWithClaims,
}

#[derive(Debug, Clone)]
pub struct RefreshSession {
    pub user: users::service::User,
    pub access_token: jwt::TokenWithClaims,
    pub refresh_token: jwt::TokenWithClaims,
    pub expires_in: u32,
    pub old_jti: String,
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("invalid credentials")]
    InvalidCredentials,

    #[error("token expired or invalid")]
    InvalidToken,

    #[error("user already exists")]
    UserAlreadyExists,

    #[error("password hashing failed: {0}")]
    PasswordHashingFailed(#[from] argon2::password_hash::Error),

    #[error("jwt operation failed: {0}")]
    JwtOperationFailed(#[from] jwt::JwtError),

    #[error("token operation failed: {0}")]
    TokenOperationFailed(#[from] tokens::TokenError),

    // #[error("user operation failed: {0}")]
    // UserOperationFailed(#[from] users::service::UserError),
    #[error("database error: {0}")]
    Database(#[from] RepoError),

    #[error("internal error: {0}")]
    Internal(String),
}

pub trait RefreshTokenRepo: Send + Sync {
    fn create(
        &self,
        db: &SqlContext,
        command: CreateRefreshTokenCommand,
    ) -> impl std::future::Future<Output = Result<(), RepoError>> + Send;

    fn revoke_by_jti(
        &self,
        db: &SqlContext,
        jti: &str,
    ) -> impl std::future::Future<Output = Result<(), RepoError>> + Send;

    fn find_by_jti(
        &self,
        db: &SqlContext,
        tenant_id: users::service::TenantId,
        jti: &str,
    ) -> impl std::future::Future<Output = Result<RefreshToken, RepoError>> + Send;

    fn revoke_all_for_user(
        &self,
        db: &SqlContext,
        tenant_id: users::service::TenantId,
        user_id: users::service::UserId,
    ) -> impl std::future::Future<Output = Result<(), RepoError>> + Send;
}

#[derive(Clone)]
pub struct AuthService<
    UR: crate::identity::users::service::UserRepo,
    R: RefreshTokenRepo,
> {
    users: users::service::UserService<UR>,
    refresh_tokens: R,
}

impl<UR: crate::identity::users::service::UserRepo, R: RefreshTokenRepo> AuthService<UR, R> {
    #[must_use]
    pub const fn new(users: users::service::UserService<UR>, refresh_tokens: R) -> Self {
        Self { users, refresh_tokens }
    }

    pub async fn login(&self, ctx: &ArcContext, command: LoginCommand) -> Result<AuthSession, AuthError> {
        let maybe_user = self.users.get_user_for_auth(&ctx.db, &command.email).await?;

        if let Some(ref record) = maybe_user
            && is_temporarily_locked(record)
        {
            return Err(AuthError::InvalidCredentials);
        }

        let password_hash = maybe_user
            .as_ref()
            .and_then(|record| record.password_hash.as_deref())
            .ok_or_else(|| {
                let _ = util::verify_password(&command.password, DUMMY_HASH);
                AuthError::InvalidCredentials
            })?;

        if !util::verify_password(&command.password, password_hash)? {
            if let Some(record) = &maybe_user {
                self.users.record_failed_login(&ctx.db, record.user.id).await?;
            }
            return Err(AuthError::InvalidCredentials);
        }

        let record = maybe_user.ok_or(AuthError::InvalidCredentials)?;
        self.users.reset_failed_login(&ctx.db, record.user.id).await?;
        self.issue_session(ctx, record.user).await
    }

    pub async fn issue_session(&self, ctx: &ArcContext, user: users::service::User) -> Result<AuthSession, AuthError> {
        let access_token = generate_access_token(ctx, &user)?;
        let refresh_token = generate_refresh_token(ctx, &user)?;
        let refresh_token_hash = tokens::get_token_hash_as_hex(&refresh_token.value);
        let refresh_token_expires_at = jwt::get_token_expiration_as_naive_utc(refresh_token.claims.exp)?;

        let cmd = CreateRefreshTokenCommand {
            jti: refresh_token.claims.jti.clone(),
            tenant_id: user.tenant_id,
            user_id: user.id,
            token_hash: refresh_token_hash.clone(),
            expires_at: refresh_token_expires_at,
        };

        self.refresh_tokens.create(&ctx.db, cmd).await?;

        Ok(AuthSession {
            user,
            access_token,
            refresh_token,
        })
    }

    pub async fn revoke_refresh_from_request(
        &self,
        ctx: &ArcContext,
        refresh_token_value: Option<&str>,
    ) -> Result<(), AuthError> {
        let Some(refresh_token_value) = refresh_token_value else {
            return Ok(());
        };

        let Ok(claims) = jwt::decode_token(&ctx.jwt, refresh_token_value, jwt::TokenType::Refresh) else {
            return Ok(());
        };

        self.refresh_tokens.revoke_by_jti(&ctx.db, &claims.jti).await?;
        Ok(())
    }

    pub async fn refresh(&self, ctx: &ArcContext, refresh_token_value: &str) -> Result<RefreshSession, AuthError> {
        let claims = jwt::decode_token(&ctx.jwt, refresh_token_value, jwt::TokenType::Refresh)?;
        let stored_token = self
            .refresh_tokens
            .find_by_jti(&ctx.db, users::service::TenantId(claims.tenant_id), &claims.jti)
            .await?;

        if stored_token.revoked_at.is_some() {
            let _ = self
                .refresh_tokens
                .revoke_all_for_user(
                    &ctx.db,
                    users::service::TenantId(claims.tenant_id),
                    stored_token.user_id,
                )
                .await;
            return Err(AuthError::InvalidToken);
        }

        let token_hash = tokens::get_token_hash_as_hex(refresh_token_value);
        if stored_token.token_hash != token_hash {
            return Err(AuthError::InvalidToken);
        }

        self.refresh_tokens.revoke_by_jti(&ctx.db, &claims.jti).await?;

        let user = self.users.get_user(&ctx.db, stored_token.user_id).await?;
        let access_token = generate_access_token(ctx, &user)?;
        let refresh_token = generate_refresh_token(ctx, &user)?;
        let refresh_token_hash = tokens::get_token_hash_as_hex(&refresh_token.value);
        let refresh_token_expires_at = jwt::get_token_expiration_as_naive_utc(refresh_token.claims.exp)?;

        self.refresh_tokens
            .create(
                &ctx.db,
                CreateRefreshTokenCommand {
                    jti: refresh_token.claims.jti.clone(),
                    tenant_id: user.tenant_id,
                    user_id: user.id,
                    token_hash: refresh_token_hash.clone(),
                    expires_at: refresh_token_expires_at,
                },
            )
            .await?;

        Ok(RefreshSession {
            expires_in: ctx.settings.jwt.access_token_expiry_minutes * 60,
            user,
            access_token,
            refresh_token,
            old_jti: claims.jti,
        })
    }
}



fn is_temporarily_locked(record: &users::service::UserAuthRecord) -> bool {
    if record.failed_login_count < constants::auth::FAILED_LOGIN_MAX_ATTEMPTS {
        return false;
    }
    record.last_failed_login.is_some_and(|last| {
        chrono::Utc::now().naive_utc() - last < chrono::Duration::minutes(constants::auth::FAILED_LOGIN_WINDOW_MINUTES)
    })
}

fn generate_refresh_token(ctx: &ArcContext, user: &users::service::User) -> Result<jwt::TokenWithClaims, AuthError> {
    Ok(jwt::generate_token(
        &ctx.jwt,
        user.id.0,
        user.tenant_id.0,
        user.email.as_str(),
        jwt::TokenType::Refresh,
        ctx.jwt.refresh_token_expiry,
    )?)
}

fn generate_access_token(ctx: &ArcContext, user: &users::service::User) -> Result<jwt::TokenWithClaims, AuthError> {
    Ok(jwt::generate_token(
        &ctx.jwt,
        user.id.0,
        user.tenant_id.0,
        user.email.as_str(),
        jwt::TokenType::Access,
        ctx.jwt.access_token_expiry,
    )?)
}

#[allow(clippy::match_same_arms)]
impl From<users::service::UserError> for AuthError {
    fn from(error: users::service::UserError) -> Self {
        match error {
            users::service::UserError::NotFound => Self::InvalidCredentials,
            users::service::UserError::AlreadyExists => Self::UserAlreadyExists,
            users::service::UserError::InvalidEmail => Self::InvalidCredentials,
            users::service::UserError::Database(e) => Self::Database(e),
        }
    }
}
