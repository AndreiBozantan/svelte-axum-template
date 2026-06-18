use std::fs;
use std::path::Path;
use std::path::PathBuf;

use config::Environment;
use config::File;
use serde::Deserialize;
use serde::Serialize;

use crate::platform::constants;

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

    #[serde(default)]
    pub rate_limiter: RateLimiterSettings,
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
            url: "sqlite:data/db.sqlite".to_string(),
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

#[derive(Clone, Deserialize, Serialize)]
pub struct OAuthSettings {
    #[serde(default)]
    pub google_client_id: String,

    #[serde(default, serialize_with = "serialize_masked_secret")]
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
            google_redirect_uri: String::new(),
            session_timeout_minutes: default_session_timeout(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ServerSettings {
    #[serde(default)]
    pub env: String,

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
            env: constants::env::PRODUCTION.to_string(),
            host: "0.0.0.0".to_string(),
            port: 3000,
            log_directives: "info,tower_http=info,axum=info".to_string(),
            env_vars_prefix: "APP".to_string(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    IoOperationFailed(#[from] std::io::Error),

    #[error("Failed to build or parse configuration: {0}")]
    ConfigParsingFailed(#[from] ::config::ConfigError),

    #[error("TOML serialization error: {0}")]
    SerializationFailed(#[from] toml::ser::Error),
}

impl AppSettings {
    pub fn new() -> Result<Self, Error> {
        let config_dir = Self::get_config_dir()?;
        let mut builder = ::config::Config::builder();

        // layer 0: set defaults from AppSettings::default()
        let default_settings = Self::default();
        let default_toml = toml::to_string(&default_settings)?;
        builder = builder.add_source(File::from_str(&default_toml, ::config::FileFormat::Toml));

        // layer 1: add common configuration from files
        let common_config_path = config_dir.join("configs.common.toml");
        if common_config_path.exists() {
            builder = builder.add_source(File::from(common_config_path));
        }

        // clone the builder so we don't mutate the original builder state prematurely
        let partial_config = builder.clone().build()?.try_deserialize::<Self>()?;
        // extract the app_run_env from the common config, which will determine which environment-specific config file to load
        let app_run_env = partial_config.server.env.as_str();

        // layer 2: add environment-specific config
        let env_config_path = config_dir.join(format!("configs.{app_run_env}.toml"));
        let env_config_exists = env_config_path.exists();
        if env_config_exists {
            builder = builder.add_source(File::from(env_config_path.as_path()));
        }

        // layer 3: add local config overrides
        let local_config_path = config_dir.join("configs.local.toml");
        if local_config_path.exists() {
            builder = builder.add_source(File::from(local_config_path));
        }

        // layer 4: override with environment variables (APP__SERVER__HOST, APP__DATABASE__URL, etc.)
        // use partial loaded config to extract the env_vars_prefix
        let partial_config = builder.clone().build()?.try_deserialize::<Self>()?;
        builder = builder.add_source(Environment::with_prefix(&partial_config.server.env_vars_prefix).separator("__"));

        // build the config
        let settings = builder.build()?.try_deserialize::<Self>()?;

        // in the production environment, create the config file if it doesn't exist
        // this allows users to easily modify the file without needing to copy it during deployment
        if app_run_env == constants::env::PRODUCTION && !env_config_exists {
            println!("Creating default config file at {}", env_config_path.to_string_lossy());
            let settings_str = toml::to_string(&settings)?;
            fs::write(&env_config_path, settings_str)?;
        }

        Ok(settings)
    }

    #[must_use]
    pub fn get_server_address(&self) -> String {
        format!("{}:{}", self.server.host, self.server.port)
    }

    pub fn get_config_dir() -> Result<PathBuf, std::io::Error> {
        fs::create_dir_all("./data/")?;
        Path::new("./data/").canonicalize()
    }

    #[allow(clippy::unused_self)]
    pub fn get_config_dir_str(&self) -> Result<String, std::io::Error> {
        Self::get_config_dir().map(|p| p.to_string_lossy().into_owned())
    }
}

fn serialize_masked_secret<S>(
    secret: &str,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    if secret.is_empty() {
        serializer.serialize_str("")
    } else {
        serializer.serialize_str("[REDACTED]")
    }
}

impl std::fmt::Debug for OAuthSettings {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        let google_client_secret = match self.google_client_secret.as_str() {
            "" => String::new(),
            _ => "[REDACTED]".to_string(),
        };
        f.debug_struct("OAuthSettings")
            .field("session_timeout_minutes", &self.session_timeout_minutes)
            .field("google_redirect_uri", &self.google_redirect_uri)
            .field("google_client_id", &self.google_client_id)
            .field("google_client_secret", &google_client_secret)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RateLimiterSettings {
    #[serde(default)]
    pub global: RateLimitConfig,

    #[serde(default)]
    pub login: RateLimitConfig,
}

impl Default for RateLimiterSettings {
    fn default() -> Self {
        Self {
            global: RateLimitConfig {
                enabled: true,
                rate: 10,
                period_in_seconds: 1,
                burst_size: 50,
            },
            login: RateLimitConfig {
                enabled: true,
                rate: 10,
                period_in_seconds: 60,
                burst_size: 10,
            },
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RateLimitConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub rate: u32,

    #[serde(default)]
    pub period_in_seconds: u64,

    #[serde(default)]
    pub burst_size: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rate: 1,
            period_in_seconds: 1,
            burst_size: 1,
        }
    }
}
