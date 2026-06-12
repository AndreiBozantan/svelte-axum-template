use crate::platform::auth;
use crate::platform::common;
use crate::platform::constants;
use crate::platform::identity::tokens;
use crate::platform::identity::users;
use crate::platform::jwt;

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
    ) -> Result<users::User, auth::Error> {
        let password_hash = auth::hash_password(password)?;
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
    ) -> Result<AuthResult, auth::Error> {
        let maybe_user = self
            .users
            .find_auth_details_by_email(&self.context.db, &command.email)
            .await?;

        if let Some(ref record) = maybe_user
            && is_temporarily_locked(record)
        {
            return Err(auth::Error::InvalidCredentials);
        }

        let dummy_hash = auth::dummy_hash()?;
        let password_hash = maybe_user
            .as_ref()
            .and_then(|record| record.password_hash.as_deref())
            .ok_or_else(|| {
                let _ = auth::verify_password(&command.password, dummy_hash);
                auth::Error::InvalidCredentials
            })?;

        if !auth::verify_password(&command.password, password_hash)? {
            if let Some(record) = &maybe_user {
                self.users
                    .increment_failed_login_count(&self.context.db, record.user.id)
                    .await?;
            }
            return Err(auth::Error::InvalidCredentials);
        }

        let record = maybe_user.ok_or(auth::Error::InvalidCredentials)?;
        self.users
            .reset_failed_login_count(&self.context.db, record.user.id)
            .await?;
        self.issue_session(record.user).await
    }

    pub async fn login_oauth(
        &self,
        command: OAuthLoginCommand,
    ) -> Result<AuthResult, auth::Error> {
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
    ) -> Result<AuthResult, auth::Error> {
        let access_token = generate_access_token(&self.context, &user)?;
        let refresh_token = generate_refresh_token(&self.context, &user)?;
        let refresh_token_hash = tokens::utils::get_token_hash_as_hex(&refresh_token.value);
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
    ) -> Result<(), auth::Error> {
        let claims = jwt::decode_token(&self.context.jwt, refresh_token_value, jwt::TokenType::Refresh)?;
        self.tokens.revoke_by_jti(&self.context.db, &claims.jti).await?;
        Ok(())
    }

    pub async fn refresh(
        &self,
        refresh_token_value: &str,
    ) -> Result<AuthResult, auth::Error> {
        let claims = jwt::decode_token(&self.context.jwt, refresh_token_value, jwt::TokenType::Refresh)?;
        let stored_token = self
            .tokens
            .find_by_jti(&self.context.db, common::TenantId(claims.tenant_id), &claims.jti)
            .await?;

        // re-using a revoked refresh token suggests token theft or session hijacking
        // as a security precaution, all active refresh tokens for this user are invalidated
        if stored_token.revoked_at.is_some() {
            let _ = self
                .tokens
                .revoke_all_for_user(
                    &self.context.db,
                    common::TenantId(claims.tenant_id),
                    stored_token.user_id,
                )
                .await;
            return Err(auth::Error::InvalidToken);
        }

        let token_hash = tokens::utils::get_token_hash_as_hex(refresh_token_value);
        if stored_token.token_hash != token_hash {
            return Err(auth::Error::InvalidToken);
        }

        self.tokens.revoke_by_jti(&self.context.db, &claims.jti).await?;

        let user = self.users.find_by_id(&self.context.db, stored_token.user_id).await?;
        let access_token = generate_access_token(&self.context, &user)?;
        let refresh_token = generate_refresh_token(&self.context, &user)?;
        let refresh_token_hash = tokens::utils::get_token_hash_as_hex(&refresh_token.value);
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
) -> Result<jwt::TokenWithClaims, auth::Error> {
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
) -> Result<jwt::TokenWithClaims, auth::Error> {
    Ok(jwt::generate_token(
        &ctx.jwt,
        user.id.0,
        user.tenant_id.0,
        user.email.as_str(),
        jwt::TokenType::Access,
    )?)
}

#[allow(clippy::match_same_arms)]
impl From<users::Error> for auth::Error {
    fn from(error: users::Error) -> Self {
        match error {
            users::Error::NotFound => Self::InvalidCredentials,
            users::Error::DatabaseOperationFailed(e) => Self::InternalFault(format!("database operation failed: {e}")),
            users::Error::AlreadyExists => Self::InternalFault("auth UserError::AlreadyExists".into()),
        }
    }
}
