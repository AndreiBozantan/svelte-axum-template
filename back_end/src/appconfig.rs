use std::path::Path;
use serde::Deserialize;
use config::{Config, ConfigError, Environment, File};

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub session_cookie_name: String,
    pub api_token: String,
    pub log_directives: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
}

impl AppConfig {
    pub fn new() -> Result<Self, ConfigError> {
        let mut builder = Config::builder()
            // Start with default values
            .set_default("server.host", "127.0.0.1")?
            .set_default("server.port", 3000)?
            .set_default("server.session_cookie_name", "axum_svelte_session")?
            .set_default("server.api_token", "123456789")?
            .set_default("server.log_directives", "svelte_axum_template=debug,tower_http=info")?
            .set_default("database.url", "sqlite:db.sqlite")?
            .set_default("database.max_connections", 5)?;

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
        let config = builder.build()?;

        // Deserialize the config into our config struct
        config.try_deserialize()
    }
}