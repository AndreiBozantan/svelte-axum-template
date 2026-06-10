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
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        let normalized = raw.trim().to_ascii_lowercase();
        if normalized.is_empty() || !normalized.contains('@') {
            return None;
        }
        Some(Self(normalized))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub struct Context {
    pub db: db::Context,
    pub jwt: jwt::Context,
    pub settings: config::AppSettings,
    pub http_client: reqwest::Client,
}

#[derive(Debug, thiserror::Error)]
pub enum ContextCreationError {
    #[error("Database error: {0}")]
    DatabaseConnectionFailed(#[from] sqlx::Error),

    #[error("JWT error: {0}")]
    JwtInitializationFailed(#[from] jwt::Error),

    #[error("HTTP Client creation error: {0}")]
    HttpClientInitializationFailed(#[from] reqwest::Error),

    #[error("Migration error: {0}")]
    MigrationFailed(#[from] crate::migrations::Error),
}

impl Context {
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

    pub async fn create(settings: config::AppSettings, jwt_secret: &str) -> Result<ArcContext, ContextCreationError> {
        let db = crate::db::create_context(&settings.database).await?;
        let jwt = crate::jwt::Context::new(&settings.jwt, jwt_secret)?;
        let http_client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        let context = Self {
            db,
            jwt,
            settings,
            http_client,
        };
        Ok(context.into())
    }

    #[cfg(any(test, feature = "test-helpers"))]
    pub async fn create_test_context() -> Result<ArcContext, ContextCreationError> {
        let settings = config::AppSettings {
            jwt: config::JwtSettings {
                access_token_expiry_minutes: 60,
                refresh_token_expiry_days: 1,
            },
            server: config::ServerSettings {
                env: crate::constants::env::TEST.to_string(),
                ..Default::default()
            },
            database: config::DatabaseSettings {
                url: "sqlite::memory:".to_string(),
                max_connections: 5,
                store_temp_tables_in_memory: true,
            },
            ..Default::default()
        };

        let jwt_secret = "test__secret__key__for__jwt__testing";
        let context = Self::create(settings, jwt_secret).await?;
        crate::migrations::run_migrations(&context).await?;

        Ok(context)
    }
}
