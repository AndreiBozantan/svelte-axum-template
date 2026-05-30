use std::{env, fs, path::Path};

use config::ConfigError;
use config::Environment;
use config::File;
use serde::Deserialize;
use serde::Serialize;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct AppSettings {
    #[serde(default)]
    pub server: ServerSettings,

    #[serde(default)]
    pub database: DatabaseSettings,

    #[serde(default)]
    pub jwt: JwtSettings,

    #[serde(default)]
    pub oauth: OAuthSettings,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DatabaseSettings {
    #[serde(default)]
    pub url: String,

    #[serde(default)]
    pub max_connections: u32,

    #[serde(default)]
    pub store_temp_tables_in_memory: bool,
}

impl Default for DatabaseSettings {
    fn default() -> Self {
        Self {
            url: "sqlite:db.sqlite".to_string(),
            max_connections: 5,
            store_temp_tables_in_memory: true,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct JwtSettings {
    #[serde(default)]
    pub access_token_expiry_minutes: u32,

    #[serde(default)]
    pub refresh_token_expiry_days: u32,
}

impl Default for JwtSettings {
    fn default() -> Self {
        Self {
            access_token_expiry_minutes: 16,
            refresh_token_expiry_days: 30,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OAuthSettings {
    #[serde(default)]
    pub google_client_id: String,

    #[serde(default)]
    pub google_client_secret: String,

    #[serde(default)]
    pub google_redirect_uri: String,

    /// Session timeout in minutes for OAuth flow
    #[serde(default = "default_session_timeout")]
    pub session_timeout_minutes: u32,
}

const fn default_session_timeout() -> u32 {
    10 // 10 minutes default
}

impl Default for OAuthSettings {
    fn default() -> Self {
        Self {
            google_client_id: String::new(),
            google_client_secret: String::new(),
            google_redirect_uri: "http://localhost:3000/api/oauth/google/callback".to_string(),
            session_timeout_minutes: default_session_timeout(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ServerSettings {
    #[serde(default)]
    pub host: String,

    #[serde(default)]
    pub port: u16,

    #[serde(default)]
    pub log_directives: String,

    #[serde(default)]
    pub env_vars_prefix: String,
}

impl Default for ServerSettings {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 3000,
            log_directives: "info,tower_http=info,axum=info".to_string(),
            env_vars_prefix: "APP".to_string(),
        }
    }
}

impl AppSettings {
    pub fn new() -> Result<Self, ConfigError> {
        dotenvy::dotenv().ok();

        let config_path = Self::get_config_path();
        let mut builder = ::config::Config::builder();

        // Layer 0: Set defaults from AppSettings::default()
        let default_settings = Self::default();
        let default_toml = toml::to_string(&default_settings)
            .map_err(|e| ConfigError::Message(format!("Failed to serialize defaults: {e}")))?;
        builder = builder.add_source(File::from_str(&default_toml, ::config::FileFormat::Toml));

        // Layer 1: Add common configuration from files
        let common_config_path = config_path.join("configs.common.toml");
        if common_config_path.exists() {
            builder = builder.add_source(File::from(common_config_path));
        }

        // extract the env_vars_prefix from the common config
        // clone the builder so we don't mutate the original builder state prematurely
        let partial_config = builder.clone().build()?.try_deserialize::<Self>()?;
        let env_vars_prefix = partial_config.server.env_vars_prefix;
        let app_run_env = Self::get_app_run_env(&env_vars_prefix);

        // Layer 2: Add environment-specific config
        let env_config_path = config_path.join(format!("configs.{app_run_env}.toml"));
        let env_config_exists = env_config_path.exists();
        if env_config_exists {
            builder = builder.add_source(File::from(env_config_path.clone()));
        }

        // Layer 3: Add local config overrides
        let local_config_path = config_path.join("configs.local.toml");
        if local_config_path.exists() {
            builder = builder.add_source(File::from(local_config_path));
        }

        // Layer 4: Override with environment variables, using a dynamic prefix
        // Use APP_SERVER_HOST, APP_DATABASE_URL, etc.
        builder = builder.add_source(Environment::with_prefix(&env_vars_prefix).separator("_"));

        // Build the config
        let settings = builder.build()?.try_deserialize::<Self>()?;

        // In the production environment, create the config file if it doesn't exist.
        // This allows users to easily modify the file without needing to copy it during deployment.
        if app_run_env == "production" && !env_config_exists {
            let settings_str = toml::to_string(&settings)
                .map_err(|e| ConfigError::Message(format!("Failed to serialize config: {e}")))?;
            fs::write(&env_config_path, settings_str)
                .map_err(|e| ConfigError::Message(format!("Failed to write config file: {e}")))?;
            println!("Created default config file at {}", env_config_path.to_string_lossy());
        }

        Ok(settings)
    }

    #[must_use]
    pub fn get_server_address(&self) -> String {
        format!("{}:{}", self.server.host, self.server.port)
    }

    #[must_use]
    pub fn get_app_run_env(env_vars_prefix: &str) -> String {
        env::var(format!("{env_vars_prefix}_RUN_ENV")).unwrap_or_else(|_| "production".to_string())
    }

    #[must_use]
    pub fn get_config_path() -> &'static Path {
        Path::new("./data/")
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
