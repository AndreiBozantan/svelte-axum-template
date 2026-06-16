use crate::platform::api;
use crate::platform::common;
use crate::platform::constants;
use crate::platform::crypto;
use crate::platform::db;
use crate::platform::jwt;
use tracing::error;

use crate::platform::identity::tokens;
use crate::platform::identity::users;

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
pub enum Error {
    #[error("invalid credentials")]
    InvalidCredentials,

    #[error("token expired or invalid")]
    InvalidToken,

    #[error("user already exists")]
    UserAlreadyExists,

    #[error("password hashing failed: {0}")]
    PasswordHashingFailed(#[from] argon2::password_hash::Error),

    #[error("jwt operation failed: {0}")]
    JwtOperationFailed(#[from] jwt::Error),

    #[error("invalid header value: {0}")]
    InvalidHeaderValue(#[from] axum::http::header::InvalidHeaderValue),

    #[error("internal error: {0}")]
    InternalFault(String),
}

impl From<Error> for api::Error {
    fn from(error: Error) -> Self {
        #[allow(clippy::enum_glob_use)]
        use Error::*;

        match error {
            JwtOperationFailed(jwt::Error::ExpiredToken) => Self::expired_token(),
            InvalidCredentials => Self::invalid_credentials(),
            UserAlreadyExists => Self::user_already_exists(),
            JwtOperationFailed(_) => Self::invalid_token(),
            InvalidHeaderValue(_) => Self::invalid_token(),
            InvalidToken => Self::invalid_token(),
            _ => Self::internal(),
        }
    }
}

impl From<db::Error> for Error {
    fn from(error: db::Error) -> Self {
        match error {
            db::Error::RowNotFound => Self::InvalidToken,
            db::Error::UniqueConstraintViolation(_) => Self::UserAlreadyExists,
            other => Self::InternalFault(format!("database operation failed {other}")),
        }
    }
}

#[derive(Clone)]
pub struct Service<UR: users::TRepository, TR: tokens::TRepository> {
    pub context: common::ArcContext,
    users: UR,
    tokens: TR,
}

impl<UR: users::TRepository, TR: tokens::TRepository> Service<UR, TR> {
    #[must_use]
    pub const fn new(
        users: UR,
        tokens: TR,
        context: common::ArcContext,
    ) -> Self {
        Self { context, users, tokens }
    }

    pub async fn register(
        &self,
        email: common::Email,
        password: &str,
        first_name: Option<String>,
        last_name: Option<String>,
    ) -> Result<users::User, Error> {
        let password_hash = crypto::hash_password(password)?;
        let cmd = users::CreateUserCommand {
            tenant_id: common::TenantId(0),
            status: users::UserStatus::Active,
            email,
            first_name,
            middle_name: None,
            last_name,
            password_hash: Some(password_hash),
            sso_provider: None,
            sso_id: None,
        };
        let user = self.users.create_user(&self.context.db, cmd).await?;
        Ok(user)
    }

    pub async fn login(
        &self,
        command: LoginCommand,
    ) -> Result<AuthResult, Error> {
        let maybe_user = self
            .users
            .find_auth_details_by_email(&self.context.db, &command.email)
            .await?;

        if let Some(ref record) = maybe_user
            && is_temporarily_locked(record)
        {
            return Err(Error::InvalidCredentials);
        }

        let dummy_hash = crypto::dummy_hash()?;
        let record = maybe_user.ok_or_else(|| {
            let _ = crypto::verify_password(&command.password, dummy_hash);
            Error::InvalidCredentials
        })?;

        let password_hash = record.password_hash.as_deref().ok_or_else(|| {
            let _ = crypto::verify_password(&command.password, dummy_hash);
            Error::InvalidCredentials
        })?;

        if !crypto::verify_password(&command.password, password_hash)? {
            self.users
                .increment_failed_login_count(&self.context.db, record.user.id)
                .await?;
            return Err(Error::InvalidCredentials);
        }

        self.users
            .reset_failed_login_count(&self.context.db, record.user.id)
            .await?;

        if crypto::needs_rehash(password_hash)? {
            self.update_password_hash(record.user.id, &command.password).await;
        }
        self.issue_session(record.user).await
    }

    pub async fn login_oauth(
        &self,
        command: OAuthLoginCommand,
    ) -> Result<AuthResult, Error> {
        let cmd = users::LinkSsoUserCommand {
            email: command.email,
            tenant_id: common::TenantId(constants::db::DEFAULT_TENANT_ID_FOR_NEW_SSO_USERS),
            sso_provider: command.sso_provider,
            sso_id: command.sso_id,
        };
        let user = self.users.link_sso_user(&self.context.db, cmd).await?;
        self.users.reset_failed_login_count(&self.context.db, user.id).await?;
        self.issue_session(user).await
    }

    pub async fn issue_session(
        &self,
        user: users::User,
    ) -> Result<AuthResult, Error> {
        let access_token = generate_access_token(&self.context, &user)?;
        let refresh_token = generate_refresh_token(&self.context, &user)?;
        let refresh_token_hash = crypto::get_hash_as_hex(&refresh_token.value);
        let refresh_token_expires_at = jwt::get_token_expiration_as_naive_utc(refresh_token.claims.exp)?;

        let cmd = tokens::CreateRefreshTokenCommand {
            jti: refresh_token.claims.jti.clone(),
            tenant_id: user.tenant_id,
            user_id: user.id,
            token_hash: refresh_token_hash.clone(),
            expires_at: refresh_token_expires_at,
        };

        self.tokens.create(&self.context.db, cmd).await?;

        Ok(AuthResult {
            user,
            access_token,
            refresh_token,
            old_jti: None,
        })
    }

    pub async fn revoke_refresh_token(
        &self,
        refresh_token_value: &str,
    ) -> Result<(), Error> {
        let claims = jwt::decode_token(&self.context.jwt, refresh_token_value, jwt::TokenType::Refresh)?;
        self.tokens.revoke_by_jti(&self.context.db, &claims.jti).await?;
        Ok(())
    }

    pub async fn refresh(
        &self,
        refresh_token_value: &str,
    ) -> Result<AuthResult, Error> {
        let claims = jwt::decode_token(&self.context.jwt, refresh_token_value, jwt::TokenType::Refresh)?;
        let tenant_id = claims.tenant_id();
        let stored_token = self
            .tokens
            .find_by_jti(&self.context.db, tenant_id, &claims.jti)
            .await?;

        let token_user_id = claims.user_id()?;
        if stored_token.user_id != token_user_id {
            return Err(Error::InvalidToken);
        }

        // re-using a revoked refresh token suggests token theft or session hijacking
        // as a security precaution, all active refresh tokens for this user are invalidated
        let user_id = stored_token.user_id;
        if stored_token.revoked_at.is_some() {
            let _ = self
                .tokens
                .revoke_all_for_user(&self.context.db, tenant_id, user_id)
                .await;
            return Err(Error::InvalidToken);
        }

        let token_hash = crypto::get_hash_as_hex(refresh_token_value);
        if stored_token.token_hash != token_hash {
            return Err(Error::InvalidToken);
        }

        // revoke the existing refresh token
        self.tokens.revoke_by_jti(&self.context.db, &claims.jti).await?;

        let user = self.users.find_by_id(&self.context.db, tenant_id, user_id).await?;
        let access_token = generate_access_token(&self.context, &user)?;
        let refresh_token = generate_refresh_token(&self.context, &user)?;
        let refresh_token_hash = crypto::get_hash_as_hex(&refresh_token.value);
        let refresh_token_expires_at = jwt::get_token_expiration_as_naive_utc(refresh_token.claims.exp)?;

        self.tokens
            .create(
                &self.context.db,
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

    async fn update_password_hash(
        &self,
        user_id: common::UserId,
        password: &str,
    ) {
        match crypto::hash_password(password) {
            Ok(new_hash) => {
                if let Err(err) = self
                    .users
                    .update_password_hash(&self.context.db, user_id, &new_hash)
                    .await
                {
                    error!(
                        user_id = user_id.0,
                        error = %err,
                        "password_rehash_update_failed"
                    );
                }
            },
            Err(err) => {
                error!(
                    user_id = user_id.0,
                    error = %err,
                    "password_rehash_failed"
                );
            },
        }
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

fn generate_refresh_token(
    ctx: &common::ArcContext,
    user: &users::User,
) -> Result<jwt::TokenWithClaims, Error> {
    Ok(jwt::generate_token(
        &ctx.jwt,
        user.id.0,
        user.tenant_id.0,
        user.email.as_str(),
        jwt::TokenType::Refresh,
    )?)
}

fn generate_access_token(
    ctx: &common::ArcContext,
    user: &users::User,
) -> Result<jwt::TokenWithClaims, Error> {
    Ok(jwt::generate_token(
        &ctx.jwt,
        user.id.0,
        user.tenant_id.0,
        user.email.as_str(),
        jwt::TokenType::Access,
    )?)
}

impl From<users::Error> for Error {
    fn from(error: users::Error) -> Self {
        match error {
            users::Error::NotFound => Self::InvalidCredentials,
            users::Error::DatabaseOperationFailed(e) => Self::InternalFault(format!("database operation failed: {e}")),
            users::Error::AlreadyExists => Self::InternalFault("auth UserError::AlreadyExists".into()),
        }
    }
}
