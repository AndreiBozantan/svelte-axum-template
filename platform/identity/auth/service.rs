use crate::common;
use crate::constants;
use crate::identity::auth;
use crate::identity::tokens;
use crate::identity::users;
use crate::jwt;

#[derive(Debug, Clone)]
pub struct LoginCommand {
    pub email: common::Email,
    pub password: String,
}

#[derive(Debug, Clone)]
pub struct OAuthLoginCommand {
    pub email: common::Email,
    pub sso_provider: String,
    pub sso_id: String,
}

#[derive(Debug, Clone)]
pub struct AuthResult {
    pub user: users::User,
    pub access_token: jwt::TokenWithClaims,
    pub refresh_token: jwt::TokenWithClaims,
    pub old_jti: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("invalid credentials")]
    InvalidCredentials,

    #[error("token expired or invalid")]
    InvalidToken,

    #[error("password hashing failed: {0}")]
    PasswordHashingFailed(#[from] argon2::password_hash::Error),

    #[error("jwt operation failed: {0}")]
    JwtOperationFailed(#[from] jwt::Error),

    #[error("token operation failed: {0}")]
    TokenOperationFailed(#[from] tokens::utils::TokenError),

    #[error("database error: {0}")]
    DatabaseOperationFailed(#[from] common::RepoError),

    #[error("internal error: {0}")]
    Internal(String),
}

#[derive(Clone)]
pub struct Service<UR: users::TRepository, TR: tokens::TRepository> {
    users: UR,
    tokens: TR,
}

impl<UR: users::TRepository, TR: tokens::TRepository> Service<UR, TR> {
    #[must_use]
    pub const fn new(users: UR, tokens: TR) -> Self {
        Self { users, tokens }
    }

    pub async fn login(&self, ctx: &common::ArcContext, command: LoginCommand) -> Result<AuthResult, AuthError> {
        let maybe_user = self.users.find_auth_details_by_email(&ctx.db, &command.email).await?;

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
                self.users.increment_failed_login_count(&ctx.db, record.user.id).await?;
            }
            return Err(AuthError::InvalidCredentials);
        }

        let record = maybe_user.ok_or(AuthError::InvalidCredentials)?;
        self.users.reset_failed_login_count(&ctx.db, record.user.id).await?;
        self.issue_session(ctx, record.user).await
    }

    pub async fn login_oauth(
        &self,
        ctx: &common::ArcContext,
        command: OAuthLoginCommand,
    ) -> Result<AuthResult, AuthError> {
        let cmd = users::LinkSsoUserCommand {
            email: command.email,
            tenant_id: common::TenantId(crate::constants::db::DEFAULT_TENANT_ID_FOR_NEW_SSO_USERS),
            sso_provider: command.sso_provider,
            sso_id: command.sso_id,
        };
        let user = self.users.link_sso_user(&ctx.db, cmd).await?;
        self.users.reset_failed_login_count(&ctx.db, user.id).await?;
        self.issue_session(ctx, user).await
    }

    pub async fn issue_session(&self, ctx: &common::ArcContext, user: users::User) -> Result<AuthResult, AuthError> {
        let access_token = generate_access_token(ctx, &user)?;
        let refresh_token = generate_refresh_token(ctx, &user)?;
        let refresh_token_hash = tokens::utils::get_token_hash_as_hex(&refresh_token.value);
        let refresh_token_expires_at = jwt::get_token_expiration_as_naive_utc(refresh_token.claims.exp)?;

        let cmd = tokens::CreateRefreshTokenCommand {
            jti: refresh_token.claims.jti.clone(),
            tenant_id: user.tenant_id,
            user_id: user.id,
            token_hash: refresh_token_hash.clone(),
            expires_at: refresh_token_expires_at,
        };

        self.tokens.create(&ctx.db, cmd).await?;

        Ok(AuthResult {
            user,
            access_token,
            refresh_token,
            old_jti: None,
        })
    }

    pub async fn revoke_refresh_token(
        &self,
        ctx: &common::ArcContext,
        refresh_token_value: &str,
    ) -> Result<(), AuthError> {
        let claims = jwt::decode_token(&ctx.jwt, refresh_token_value, jwt::TokenType::Refresh)?;
        self.tokens.revoke_by_jti(&ctx.db, &claims.jti).await?;
        Ok(())
    }

    pub async fn refresh(&self, ctx: &common::ArcContext, refresh_token_value: &str) -> Result<AuthResult, AuthError> {
        let claims = jwt::decode_token(&ctx.jwt, refresh_token_value, jwt::TokenType::Refresh)?;
        let stored_token = self
            .tokens
            .find_by_jti(&ctx.db, common::TenantId(claims.tenant_id), &claims.jti)
            .await?;

        // re-using a revoked refresh token suggests token theft or session hijacking
        // as a security precaution, all active refresh tokens for this user are invalidated
        if stored_token.revoked_at.is_some() {
            let _ = self
                .tokens
                .revoke_all_for_user(&ctx.db, common::TenantId(claims.tenant_id), stored_token.user_id)
                .await;
            return Err(AuthError::InvalidToken);
        }

        let token_hash = tokens::utils::get_token_hash_as_hex(refresh_token_value);
        if stored_token.token_hash != token_hash {
            return Err(AuthError::InvalidToken);
        }

        self.tokens.revoke_by_jti(&ctx.db, &claims.jti).await?;

        let user = self.users.find_by_id(&ctx.db, stored_token.user_id).await?;
        let access_token = generate_access_token(ctx, &user)?;
        let refresh_token = generate_refresh_token(ctx, &user)?;
        let refresh_token_hash = tokens::utils::get_token_hash_as_hex(&refresh_token.value);
        let refresh_token_expires_at = jwt::get_token_expiration_as_naive_utc(refresh_token.claims.exp)?;

        self.tokens
            .create(
                &ctx.db,
                tokens::CreateRefreshTokenCommand {
                    jti: refresh_token.claims.jti.clone(),
                    tenant_id: user.tenant_id,
                    user_id: user.id,
                    token_hash: refresh_token_hash.clone(),
                    expires_at: refresh_token_expires_at,
                },
            )
            .await?;

        Ok(AuthResult {
            user,
            access_token,
            refresh_token,
            old_jti: Some(claims.jti),
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

fn generate_refresh_token(ctx: &common::ArcContext, user: &users::User) -> Result<jwt::TokenWithClaims, AuthError> {
    Ok(jwt::generate_token(
        &ctx.jwt,
        user.id.0,
        user.tenant_id.0,
        user.email.as_str(),
        jwt::TokenType::Refresh,
    )?)
}

fn generate_access_token(ctx: &common::ArcContext, user: &users::User) -> Result<jwt::TokenWithClaims, AuthError> {
    Ok(jwt::generate_token(
        &ctx.jwt,
        user.id.0,
        user.tenant_id.0,
        user.email.as_str(),
        jwt::TokenType::Access,
    )?)
}

#[allow(clippy::match_same_arms)]
impl From<users::UserError> for AuthError {
    fn from(error: users::UserError) -> Self {
        match error {
            users::UserError::NotFound => Self::InvalidCredentials,
            users::UserError::InvalidEmail(_) => Self::InvalidCredentials,
            users::UserError::Database(e) => Self::DatabaseOperationFailed(e),
            users::UserError::AlreadyExists => Self::Internal("auth UserError::AlreadyExists".into()),
        }
    }
}

use argon2::password_hash as ar2;

/// Hash a password using Argon2
pub fn hash_password(password: &str) -> Result<String, ar2::Error> {
    use ar2::PasswordHasher;
    use argon2::Argon2;
    let salt = ar2::SaltString::generate(ar2::rand_core::OsRng);
    let hash = Argon2::default().hash_password(password.as_bytes(), &salt)?;
    Ok(hash.to_string())
}

/// Verify a password against a hash
pub fn verify_password(password: &str, hash: &str) -> Result<bool, ar2::Error> {
    use ar2::PasswordVerifier;
    use argon2::Argon2;
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
