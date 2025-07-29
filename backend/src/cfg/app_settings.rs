use config::{ConfigError, Environment, File};
use serde::Deserialize;
use std::{env, path::Path};

use crate::cfg;

// TODO: move jwt secret generation to JwtContext
// TODO: write config to file if it doesn't exist, so that it can be modified by users
// TODO: update default_config.toml to include all settings

#[derive(Clone, Debug, Default, Deserialize)]
pub struct AppSettings {
    #[serde(default)]
    pub server: cfg::ServerSettings,

    #[serde(default)]
    pub database: cfg::DatabaseSettings,

    #[serde(default)]
    pub jwt: cfg::JwtSettings,

    #[serde(default)]
    pub oauth: cfg::OAuthSettings,
}

impl AppSettings {
    pub fn new() -> Result<Self, ConfigError> {
        dotenvy::dotenv().ok();

        let app_run_env = Self::get_app_run_env();
        let config_path = Self::get_config_path();
        let mut builder = config::Config::builder();

        // Layer 1: Add default configuration from files
        let default_config_path = config_path.join("configs.default.toml");
        if default_config_path.exists() {
            builder = builder.add_source(File::from(default_config_path));
        }

        // Layer 2: Add environment-specific config
        let env_config_path = config_path.join(format!("configs.{app_run_env}.toml"));
        if env_config_path.exists() {
            builder = builder.add_source(File::from(env_config_path));
        }

        // Layer 3: Add local config overrides
        let local_config_path = config_path.join("configs.local.toml");
        if local_config_path.exists() {
            builder = builder.add_source(File::from(local_config_path));
        }

        // Layer 4: Override with environment variables
        // Use APP_SERVER_HOST, APP_DATABASE_URL, etc.
        builder = builder.add_source(Environment::with_prefix("APP").separator("_"));

        // Build the config
        let settings = builder.build()?.try_deserialize::<Self>()?;

        // if !env_config_path.exists() {
        //     fs::write(&env_config_path, toml::to_string(&config).unwrap())
        //         .map_err(|e| ConfigError::Message(format!("Failed to write config file: {}", e)))?;
        //     println!("Created default config file at {env_config_path:?}");
        // }

        Ok(settings)
    }

    #[must_use]
    pub fn get_server_address(&self) -> String {
        format!("{}:{}", self.server.host, self.server.port)
    }

    #[must_use]
    pub fn get_app_run_env() -> String {
        env::var("APP_RUN_ENV").unwrap_or_else(|_| "production".to_string())
    }

    #[must_use]
    pub fn get_config_path() -> &'static Path {
        Path::new(".")
    }

    #[must_use]
    pub fn get_config_full_path() -> String {
        let config_path = Self::get_config_path();
        config_path
            .canonicalize()
            .ok()
            .unwrap_or_else(|| config_path.to_path_buf())
            .to_string_lossy()
            .to_string()
    }
}
