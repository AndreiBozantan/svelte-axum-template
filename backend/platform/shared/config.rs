//! Configuration subsystem for the Svelaxum backend.
//!
//! This module handles loading, parsing, and validating application-wide configuration
//! settings from common, environment-specific, and local TOML files as well as
//! environment variable overrides.

use std::fs;
use std::path::Path;
use std::path::PathBuf;

use config::Environment;
use config::File;
use serde::Deserialize;
use serde::Serialize;

use crate::platform::constants;

/// Application-wide configuration settings loaded from TOML files and environment variables.
///
/// ## Configuration Layering
/// When `AppSettings::new()` is called, settings are merged in the following order (last write wins):
///
/// 1. **Code Defaults**: Hardcoded default values specified in `AppSettings::default()`.
/// 2. **Common Config** (`data/configs.common.toml`): Shared defaults used across all environments.
/// 3. **Environment Config** (`data/configs.<env>.toml`): Environment-specific overrides (where `<env>`
///    is `development`, `production`, or `test`). The environment is determined by the `APP__SERVER__ENV`
///    or `APP_ENV` environment variable, defaulting to `production`.
/// 4. **Local Overrides** (`data/configs.local.toml`): Optional git-ignored file containing local
///    settings/secrets.
/// 5. **Environment Variables**: System environment variables prefixed with `APP__` (e.g., `APP__SERVER__PORT`).
///    Keys are separated by a double underscore `__` to traverse nested settings.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct AppSettings {
    /// Configuration settings for the HTTP server.
    #[serde(default)]
    pub server: ServerSettings,

    /// Configuration settings for the `SQLite` database.
    #[serde(default)]
    pub database: DatabaseSettings,

    /// Configuration settings for JSON Web Token (JWT) lifetimes.
    #[serde(default)]
    pub jwt: JwtSettings,

    /// Configuration settings for Google `OAuth2` SSO.
    #[serde(default)]
    pub oauth: OAuthSettings,

    /// Configuration settings for the shared outbound HTTP client.
    #[serde(default)]
    pub http_client: HttpClientSettings,

    /// Configuration settings for API rate limiting.
    #[serde(default)]
    pub rate_limiter: AppRateLimiterSettings,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HttpClientSettings {
    /// Total request timeout in seconds (connect + TLS + response body).
    #[serde(default)]
    pub timeout_seconds: u64,

    /// Connection establishment timeout in seconds.
    #[serde(default)]
    pub connect_timeout_seconds: u64,
}

impl Default for HttpClientSettings {
    fn default() -> Self {
        Self {
            timeout_seconds: 10,
            connect_timeout_seconds: 5,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DatabaseSettings {
    /// The `SQLite` database connection URL (e.g., `sqlite:data/db.sqlite` or `:memory:`).
    #[serde(default)]
    pub url: String,

    /// The minimum number of connections to maintain in the database connection pool.
    #[serde(default)]
    pub min_connections: u32,

    /// The maximum number of connections to allow in the database connection pool.
    #[serde(default)]
    pub max_connections: u32,

    /// If true, `SQLite` temporary tables are stored in memory rather than on disk.
    #[serde(default)]
    pub store_temp_tables_in_memory: bool,

    /// The timeout in seconds to wait when writing to a locked database before returning a busy error.
    #[serde(default)]
    pub write_busy_timeout_seconds: u64,
}

impl Default for DatabaseSettings {
    fn default() -> Self {
        Self {
            url: "sqlite:data/db.sqlite".to_string(),
            min_connections: 2,
            max_connections: 5,
            store_temp_tables_in_memory: true,
            write_busy_timeout_seconds: 30,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct JwtSettings {
    /// The lifespan of access tokens in minutes.
    #[serde(default)]
    pub access_token_expiry_minutes: u32,

    /// The lifespan of refresh tokens in days.
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
    /// The Google `OAuth2` Client ID.
    #[serde(default)]
    pub google_client_id: String,

    /// The Google `OAuth2` Client Secret.
    #[serde(default, serialize_with = "serialize_masked_secret")]
    pub google_client_secret: String,

    /// The Google `OAuth2` Redirect URI (callback URL).
    #[serde(default)]
    pub google_redirect_uri: String,

    /// Session timeout in minutes for the OAuth flow.
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
    /// The IP address or host to bind the server to (e.g., `0.0.0.0` or `127.0.0.1`).
    #[serde(default)]
    pub host: String,

    /// The port number to bind the server to (e.g., 3000).
    #[serde(default)]
    pub port: u16,

    /// `RUST_LOG` style filter directives for structured logging (e.g., `info,tower_http=info`).
    #[serde(default)]
    pub log_directives: String,

    /// The prefix for environment variable overrides (e.g., `APP` overrides via `APP__SERVER__PORT`).
    #[serde(default)]
    pub env_vars_prefix: String,

    /// If true, trusts reverse proxy headers (like `X-Forwarded-For`) for identifying the client IP.
    #[serde(default)]
    pub trusted_proxy: bool,
}

impl Default for ServerSettings {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 3000,
            log_directives: "info,tower_http=info,axum=info".to_string(),
            env_vars_prefix: "APP".to_string(),
            trusted_proxy: false,
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

    #[error("Configuration validation failed: {0}")]
    ValidationFailed(String),
}

pub fn get_app_env() -> Result<String, Error> {
    get_app_env_impl(|key| std::env::var(key).ok())
}

pub fn get_app_env_impl<F>(lookup: F) -> Result<String, Error>
where
    F: Fn(&str) -> Option<String>,
{
    let env = lookup("APP__SERVER__ENV")
        .or_else(|| lookup("APP_ENV"))
        .unwrap_or_else(|| constants::env::PRODUCTION.to_string());

    if env != constants::env::PRODUCTION && env != constants::env::DEVELOPMENT && env != constants::env::TEST {
        return Err(Error::ValidationFailed(format!(
            "invalid server environment '{env}', must be one of: {}, {}, {}",
            constants::env::PRODUCTION,
            constants::env::DEVELOPMENT,
            constants::env::TEST
        )));
    }

    Ok(env)
}

impl AppSettings {
    pub fn new() -> Result<Self, Error> {
        let config_dir = Self::get_config_dir()?;
        let mut builder = ::config::Config::builder();

        // layer 0: set defaults from AppSettings::default()
        let default_settings = Self::default();
        let default_toml = toml::to_string(&default_settings)?;
        builder = builder.add_source(File::from_str(&default_toml, ::config::FileFormat::Toml));

        // Determine environment strictly from process environment, defaulting to production
        let app_run_env = get_app_env()?;

        // layer 1: add common configuration from files
        let common_config_path = config_dir.join("configs.common.toml");
        if common_config_path.exists() {
            builder = builder.add_source(File::from(common_config_path));
        }

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

        // Validate the configuration before returning it
        settings.validate()?;

        Ok(settings)
    }

    #[must_use]
    pub fn get_server_address(&self) -> String {
        format!("{}:{}", self.server.host, self.server.port)
    }

    pub fn validate(&self) -> Result<(), Error> {
        use std::str::FromStr;

        // validate database URL
        if self.database.url.is_empty() {
            return Err(Error::ValidationFailed("database URL cannot be empty".to_string()));
        }

        if !self.database.url.starts_with("sqlite:") && self.database.url != ":memory:" {
            return Err(Error::ValidationFailed(
                "invalid database URL: must start with 'sqlite:' or be ':memory:'".to_string(),
            ));
        }

        sqlx::sqlite::SqliteConnectOptions::from_str(&self.database.url)
            .map_err(|err| Error::ValidationFailed(format!("invalid database URL: {err}")))?;

        // validate OAuth settings if any OAuth field is set
        let has_oauth_field = !self.oauth.google_client_id.is_empty()
            || !self.oauth.google_client_secret.is_empty()
            || !self.oauth.google_redirect_uri.is_empty();

        if has_oauth_field {
            if self.oauth.google_client_id.is_empty() {
                return Err(Error::ValidationFailed(
                    "Google Client ID is required when OAuth is configured".to_string(),
                ));
            }
            if self.oauth.google_client_secret.is_empty() {
                return Err(Error::ValidationFailed(
                    "Google Client Secret is required when OAuth is configured".to_string(),
                ));
            }
            if self.oauth.google_redirect_uri.is_empty() {
                return Err(Error::ValidationFailed(
                    "Google Redirect URI is required when OAuth is configured".to_string(),
                ));
            }

            let parsed = url::Url::parse(&self.oauth.google_redirect_uri)
                .map_err(|err| Error::ValidationFailed(format!("invalid Google redirect URI: {err}")))?;

            let host = parsed.host_str().unwrap_or("");
            let is_localhost = host == "localhost" || host == "127.0.0.1" || host == "::1";
            if parsed.scheme() != "https" && !is_localhost {
                return Err(Error::ValidationFailed(
                    "Google Redirect URI must use HTTPS in non-localhost environments".to_string(),
                ));
            }
        }

        Ok(())
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
pub struct AppRateLimiterSettings {
    /// Rate limit configuration applied globally to all endpoints.
    #[serde(default)]
    pub global: RateLimitSettings,

    /// Rate limit configuration applied specifically to auth/login/register endpoints.
    #[serde(default)]
    pub login: RateLimitSettings,
}

impl Default for AppRateLimiterSettings {
    fn default() -> Self {
        Self {
            global: RateLimitSettings {
                enabled: true,
                rate: 10,
                period_in_seconds: 1,
                burst_size: 50,
            },
            login: RateLimitSettings {
                enabled: true,
                rate: 10,
                period_in_seconds: 60,
                burst_size: 10,
            },
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RateLimitSettings {
    /// If true, rate limiting is enabled for this category.
    #[serde(default)]
    pub enabled: bool,

    /// The number of allowed requests per period.
    #[serde(default)]
    pub rate: u32,

    /// The duration of the measurement period in seconds.
    #[serde(default)]
    pub period_in_seconds: u64,

    /// The capacity of the token bucket (maximum requests allowed in a sudden burst).
    #[serde(default)]
    pub burst_size: u32,
}

impl Default for RateLimitSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            rate: 1,
            period_in_seconds: 1,
            burst_size: 1,
        }
    }
}
