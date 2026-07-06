use crate::platform::config;
use crate::platform::constants;
use crate::platform::db;
use crate::platform::jwt;
use crate::platform::migrations;

pub type ArcContext = std::sync::Arc<Context>;
// pub type AppContext = axum::extract::State<ArcContext>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UserId(pub i64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TenantId(pub i64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Email(String);

impl Email {
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        use validator::ValidateEmail;
        let normalized = raw.trim().to_ascii_lowercase();
        if normalized.validate_email() {
            return Some(Self(normalized));
        }
        None
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
    MigrationFailed(#[from] migrations::Error),
}

impl Context {
    #[must_use]
    pub fn env(&self) -> &str {
        &self.settings.server.env
    }

    #[must_use]
    pub fn is_prod_env(&self) -> bool {
        self.settings.server.env == constants::env::PRODUCTION
    }

    #[must_use]
    pub fn is_dev_env(&self) -> bool {
        self.settings.server.env == constants::env::DEVELOPMENT
    }

    #[must_use]
    pub fn is_test_env(&self) -> bool {
        self.settings.server.env == constants::env::TEST
    }

    pub async fn create(
        settings: config::AppSettings,
        jwt_secret: &str,
    ) -> Result<ArcContext, ContextCreationError> {
        let db = db::create_context(&settings.database).await?;
        let jwt = jwt::create_context(&settings.jwt, jwt_secret);
        let http_client = create_http_client(&settings.http_client)?;
        let context = Self {
            db,
            jwt,
            settings,
            http_client,
        };
        // eagerly initialize the dummy password hash to prevent cold-start timing leaks
        let _ = crate::platform::crypto::dummy_hash();
        Ok(context.into())
    }

    pub async fn create_test_context() -> Result<ArcContext, ContextCreationError> {
        let settings = config::AppSettings {
            jwt: config::JwtSettings {
                access_token_expiry_minutes: 60,
                refresh_token_expiry_days: 1,
            },
            server: config::ServerSettings {
                env: constants::env::TEST.to_string(),
                ..Default::default()
            },
            database: config::DatabaseSettings {
                url: "sqlite::memory:".to_string(),
                min_connections: 1,
                max_connections: 1,
                store_temp_tables_in_memory: true,
                write_busy_timeout_seconds: 30,
            },
            rate_limiter: config::AppRateLimiterSettings {
                global: config::RateLimitSettings {
                    enabled: false,
                    ..Default::default()
                },
                login: config::RateLimitSettings {
                    enabled: false,
                    ..Default::default()
                },
            },
            ..Default::default()
        };

        let jwt_secret = "test__secret__key__for__jwt__testing";
        let context = Self::create(settings, jwt_secret).await?;
        migrations::run_migrations(&context).await?;

        Ok(context)
    }
}

fn create_http_client(settings: &config::HttpClientSettings) -> Result<reqwest::Client, reqwest::Error> {
    let mut builder = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none());
    // a configured value of 0 means "no timeout"
    if settings.timeout_seconds > 0 {
        builder = builder.timeout(std::time::Duration::from_secs(settings.timeout_seconds));
    }
    if settings.connect_timeout_seconds > 0 {
        builder = builder.connect_timeout(std::time::Duration::from_secs(settings.connect_timeout_seconds));
    }
    builder.build()
}
