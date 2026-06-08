use thiserror::Error;

use crate::config;
use crate::db;
use crate::jwt;
pub type ArcContext = std::sync::Arc<Context>;
pub type AppContext = axum::extract::State<ArcContext>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UserId(pub i64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TenantId(pub i64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Email(String);

impl Email {
    pub fn parse(raw: &str) -> Result<Self, DataValidationError> {
        let normalized = raw.trim().to_ascii_lowercase();
        if normalized.is_empty() || !normalized.contains('@') {
            return Err(DataValidationError::InvalidEmail);
        }
        Ok(Self(normalized))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Error)]
pub enum DataValidationError {
    #[error("invalid email address")]
    InvalidEmail,
}



pub struct Context {
    pub db: db::Context,
    pub jwt: jwt::Context,
    pub settings: config::AppSettings,
    pub http_client: reqwest::Client,
}


impl Context {
    #[must_use]
    pub const fn new(
        db: db::Context,
        jwt: jwt::Context,
        settings: config::AppSettings,
        http_client: reqwest::Client,
    ) -> Self {
        Self {
            db,
            jwt,
            settings,
            http_client,
        }
    }

    #[must_use]
    pub fn env(&self) -> &str {
        &self.settings.server.env
    }

    #[must_use]
    pub fn is_prod_env(&self) -> bool {
        self.settings.server.env == crate::constants::env::PRODUCTION
    }

    #[must_use]
    pub fn is_dev_env(&self) -> bool {
        self.settings.server.env == crate::constants::env::DEVELOPMENT
    }

    #[must_use]
    pub fn is_test_env(&self) -> bool {
        self.settings.server.env == crate::constants::env::TEST
    }
}

