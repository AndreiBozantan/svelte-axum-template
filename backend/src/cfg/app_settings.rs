use config::{ConfigError, Environment, File};
use serde::Deserialize;
use std::{env, fs, path::Path};

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

pub struct AppSettingsMetadata {
    pub app_run_env: String,
    pub config_dir: String,
    pub server_address: String,
    pub log_directives: String,
}

impl AppSettings {
    pub fn new() -> Result<Self, ConfigError> {
        let app_run_env = Self::get_app_run_env();
        let config_dir = Self::get_config_dir();
        let config_path = Path::new(&config_dir);
        let mut builder = config::Config::builder();

        // Layer 1: Add default configuration from files
        let default_config_path = config_path.join("default.toml");
        if default_config_path.exists() {
            builder = builder.add_source(File::from(default_config_path));
        }

        // Layer 2: Add environment-specific config
        let env_config_path = config_path.join(format!("{app_run_env}.toml"));
        if env_config_path.exists() {
            builder = builder.add_source(File::from(env_config_path));
        }

        // Layer 3: Add local config overrides
        let local_config_path = config_path.join("local.toml");
        if local_config_path.exists() {
            builder = builder.add_source(File::from(local_config_path));
        }

        // Layer 4: Override with environment variables
        // Use APP_SERVER_HOST, APP_DATABASE_URL, etc.
        builder = builder.add_source(Environment::with_prefix("APP").separator("_"));

        // Build the config
        let mut settings = builder.build()?.try_deserialize::<Self>()?;

        // handle JWT secret initialization
        settings.jwt.secret = Self::ensure_jwt_secret(config_path)?;

        // if !env_config_path.exists() {
        //     fs::write(&env_config_path, toml::to_string(&config).unwrap())
        //         .map_err(|e| ConfigError::Message(format!("Failed to write config file: {}", e)))?;
        //     println!("Created default config file at {env_config_path:?}");
        // }

        Ok(settings)
    }

    #[must_use]
    pub fn get_metadata(&self) -> AppSettingsMetadata {
        let config_dir = Self::get_config_dir();
        let config_path = Path::new(&config_dir);
        let config_dir = config_path
            .canonicalize()
            .ok()
            .map_or(config_dir, |p| p.to_string_lossy().to_string());
        AppSettingsMetadata {
            app_run_env: Self::get_app_run_env(),
            config_dir,
            server_address: format!("{}:{}", self.server.host, self.server.port),
            log_directives: self.server.log_directives.clone(),
        }
    }

    fn ensure_jwt_secret(config_path: &Path) -> Result<String, ConfigError> {
        // Priority 1: Check environment variable
        if let Ok(env_secret) = std::env::var("APP_JWT_SECRET") {
            if !env_secret.is_empty() && env_secret.len() >= 32 {
                return Ok(env_secret);
            }
        }

        // Priority 2: Check persisted secret file
        let secret_file_path = config_path.join(".jwt_secret");
        if let Ok(file_secret) = fs::read_to_string(&secret_file_path) {
            let trimmed_secret = file_secret.trim();
            if !trimmed_secret.is_empty() && trimmed_secret.len() >= 32 {
                return Ok(trimmed_secret.to_string());
            }
        }

        // Priority 3: Generate new secret and persist it
        let new_secret = Self::generate_secure_secret();

        // Create config directory if it doesn't exist
        if let Some(parent) = &secret_file_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| ConfigError::Message(format!("Failed to create config directory: {e}")))?;
        }

        // Write the secret to file with restricted permissions
        fs::write(&secret_file_path, &new_secret)
            .map_err(|e| ConfigError::Message(format!("Failed to write JWT secret to file: {e}")))?;

        // Set file permissions to be readable only by owner (Unix-like systems)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&secret_file_path)
                .map_err(|e| ConfigError::Message(format!("Failed to get file metadata: {e}")))?
                .permissions();
            perms.set_mode(0o600); // rw-------
            fs::set_permissions(&secret_file_path, perms)
                .map_err(|e| ConfigError::Message(format!("Failed to set file permissions: {e}")))?;
        }

        tracing::info!(
            "Generated new JWT secret and saved to {}",
            secret_file_path.to_string_lossy()
        );
        Ok(new_secret)
    }

    fn generate_secure_secret() -> String {
        use rand::Rng;
        let random_bytes: [u8; 32] = rand::rng().random();
        hex::encode(random_bytes)
    }

    fn get_app_run_env() -> String {
        env::var("APP_RUN_ENV").unwrap_or_else(|_| "production".to_string())
    }

    fn get_config_dir() -> String {
        "config".to_string()
    }
}
