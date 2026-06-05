use chrono::NaiveDateTime;
use thiserror::Error;

use crate::common::ArcContext;
use crate::common::RepoError;
use crate::common::SqlContext;
use crate::constants;
use crate::identity::auth;
use crate::identity::users;
use crate::jwt;

use crate::internal::tokens;

#[derive(Debug, Clone)]
pub struct LoginCommand {
    pub email: users::Email,
    pub password: String,
}

#[derive(Debug, Clone)]
pub struct CreateRefreshTokenCommand {
    pub jti: String,
    pub tenant_id: users::TenantId,
    pub user_id: users::UserId,
    pub token_hash: String,
    pub expires_at: NaiveDateTime,
}

#[derive(Debug, Clone)]
pub struct RefreshToken {
    pub user_id: users::UserId,
    pub token_hash: String,
    pub revoked_at: Option<NaiveDateTime>,
}

#[derive(Debug, Clone)]
pub struct AuthSession {
    pub user: users::User,
    pub access_token: jwt::TokenWithClaims,
    pub refresh_token: jwt::TokenWithClaims,
}

#[derive(Debug, Clone)]
pub struct RefreshSession {
    pub user: users::User,
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
        tenant_id: users::TenantId,
        jti: &str,
    ) -> impl std::future::Future<Output = Result<RefreshToken, RepoError>> + Send;

    fn revoke_all_for_user(
        &self,
        db: &SqlContext,
        tenant_id: users::TenantId,
        user_id: users::UserId,
    ) -> impl std::future::Future<Output = Result<(), RepoError>> + Send;
}

#[derive(Clone)]
pub struct Service<
    UR: crate::identity::users::UserRepo,
    TR: RefreshTokenRepo,
> {
    users: users::Service<UR>,
    refresh_tokens: TR,
}

impl<UR: users::UserRepo, TR: RefreshTokenRepo> Service<UR, TR> {
    #[must_use]
    pub const fn new(users: users::Service<UR>, refresh_tokens: TR) -> Self {
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
                let _ = auth::verify_password(&command.password, DUMMY_HASH);
                AuthError::InvalidCredentials
            })?;

        if !auth::verify_password(&command.password, password_hash)? {
            if let Some(record) = &maybe_user {
                self.users.record_failed_login(&ctx.db, record.user.id).await?;
            }
            return Err(AuthError::InvalidCredentials);
        }

        let record = maybe_user.ok_or(AuthError::InvalidCredentials)?;
        self.users.reset_failed_login(&ctx.db, record.user.id).await?;
        self.issue_session(ctx, record.user).await
    }

    pub async fn issue_session(&self, ctx: &ArcContext, user: users::User) -> Result<AuthSession, AuthError> {
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
            .find_by_jti(&ctx.db, users::TenantId(claims.tenant_id), &claims.jti)
            .await?;

        if stored_token.revoked_at.is_some() {
            let _ = self
                .refresh_tokens
                .revoke_all_for_user(
                    &ctx.db,
                    users::TenantId(claims.tenant_id),
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



fn is_temporarily_locked(record: &users::UserAuthRecord) -> bool {
    if record.failed_login_count < constants::auth::FAILED_LOGIN_MAX_ATTEMPTS {
        return false;
    }
    record.last_failed_login.is_some_and(|last| {
        chrono::Utc::now().naive_utc() - last < chrono::Duration::minutes(constants::auth::FAILED_LOGIN_WINDOW_MINUTES)
    })
}

fn generate_refresh_token(ctx: &ArcContext, user: &users::User) -> Result<jwt::TokenWithClaims, AuthError> {
    Ok(jwt::generate_token(
        &ctx.jwt,
        user.id.0,
        user.tenant_id.0,
        user.email.as_str(),
        jwt::TokenType::Refresh,
        ctx.jwt.refresh_token_expiry,
    )?)
}

fn generate_access_token(ctx: &ArcContext, user: &users::User) -> Result<jwt::TokenWithClaims, AuthError> {
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
impl From<users::UserError> for AuthError {
    fn from(error: users::UserError) -> Self {
        match error {
            users::UserError::NotFound => Self::InvalidCredentials,
            users::UserError::AlreadyExists => Self::UserAlreadyExists,
            users::UserError::InvalidEmail => Self::InvalidCredentials,
            users::UserError::Database(e) => Self::Database(e),
        }
    }
}

use argon2::Argon2;
use argon2::password_hash as ar2;

/// Hash a password using Argon2
pub fn hash_password(password: &str) -> Result<String, ar2::Error> {
    use argon2::password_hash::PasswordHasher;
    let salt = ar2::SaltString::generate(ar2::rand_core::OsRng);
    let hash = Argon2::default().hash_password(password.as_bytes(), &salt)?;
    Ok(hash.to_string())
}

/// Verify a password against a hash
pub fn verify_password(password: &str, hash: &str) -> Result<bool, ar2::Error> {
    use argon2::password_hash::PasswordVerifier;
    let parsed_hash = ar2::PasswordHash::new(hash)?;
    match Argon2::default().verify_password(password.as_bytes(), &parsed_hash) {
        Ok(()) => Ok(true),
        Err(ar2::Error::Password) => Ok(false),
        Err(e) => Err(e),
    }
}

/// A pre-computed Argon2 hash of a dummy password, used to perform a
/// constant-time "wasted" verify when the requested user does not exist,
/// preventing user-enumeration via response-time differences.
pub static DUMMY_HASH: &str = "$argon2id$\
    v=19$m=19456,t=2,p=1$\
    HfRKx+hpIQ18rfUQ5TuA5g$Zq2p1OruNc6cZAgJmgnTIs3XpBLKdrM/DujpWOPAMwQ"; // semgrep: ignore
