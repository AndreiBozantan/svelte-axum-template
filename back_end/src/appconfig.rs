use std::path::Path;
use serde::Deserialize;
use config::{Config, ConfigError, Environment, File};

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    #[serde(default)]
    pub host: String,

    #[serde(default)]
    pub port: u16,

    #[serde(default)]
    pub session_cookie_name: String,

    #[serde(default)]
    pub log_directives: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DatabaseConfig {
    #[serde(default)]
    pub url: String,

    #[serde(default)]
    pub max_connections: u32,
}

#[derive(Debug, Deserialize, Clone)]
pub struct JwtConfig {
    #[serde(default)]
    pub secret: String,

    #[serde(default)]
    pub access_token_expiry: i64,  // In seconds (e.g., 15 minutes = 900)

    #[serde(default)]
    pub refresh_token_expiry: i64, // In seconds (e.g., 7 days = 604800)
}

#[derive(Debug, Deserialize, Clone)]
pub struct AppConfig {
    #[serde(default)]
    pub server: ServerConfig,

    #[serde(default)]
    pub database: DatabaseConfig,

    #[serde(default)]
    pub jwt: JwtConfig,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 3000,
            session_cookie_name: "axum_svelte_session".to_string(),
            log_directives: "svelte_axum_template=debug,tower_http=info".to_string(),
        }
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: "sqlite:db.sqlite".to_string(),
            max_connections: 5,
        }
    }
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            secret: "your-secret-key-change-this-in-production".to_string(),
            access_token_expiry: 15 * 60,    // 15 minutes
            refresh_token_expiry: 90 * 24 * 60 * 60, // 90 days
        }
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            database: DatabaseConfig::default(),
            jwt: JwtConfig::default(),
        }
    }
}

impl AppConfig {
    pub fn new() -> Result<Self, ConfigError> {
        let mut builder = Config::builder();

        // Layer 1: Add default configuration from files
        if Path::new("./config/default.toml").exists() {
            builder = builder.add_source(File::with_name("./config/default.toml"));
        }

        // Layer 2: Add environment-specific config
        let env = std::env::var("RUN_ENV").unwrap_or_else(|_| "development".to_string());
        let env_config = format!("./config/{env}.toml");
        if Path::new(&env_config).exists() {
            builder = builder.add_source(File::with_name(&env_config));
        }

        // Layer 3: Add local config overrides
        if Path::new("./config/local.toml").exists() {
            builder = builder.add_source(File::with_name("./config/local.toml"));
        }

        // Layer 4: Override with environment variables
        // Use APP_SERVER_HOST, APP_DATABASE_URL, etc.
        builder = builder.add_source(Environment::with_prefix("APP").separator("_"));

        // Build the config
        let config = builder
            .build()?
            .try_deserialize()
            .unwrap_or_default();

        Ok(config)
    }
}