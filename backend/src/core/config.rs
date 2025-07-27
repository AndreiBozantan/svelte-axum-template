use config::{ConfigError, Environment, File};
use serde::Deserialize;
use std::{env, fs, path::Path};

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    #[serde(default)]
    pub host: String,

    #[serde(default)]
    pub port: u16,

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
    pub secret: String, // TODO: should this be removed from here?

    #[serde(default)]
    pub access_token_expiry: i64, // In seconds (e.g., 15 minutes = 900)

    #[serde(default)]
    pub refresh_token_expiry: i64, // In seconds (e.g., 7 days = 604800)
}

#[derive(Debug, Deserialize, Clone)]
pub struct OAuthConfig {
    #[serde(default)]
    pub google_client_id: String,

    #[serde(default)]
    pub google_client_secret: String,

    #[serde(default)]
    pub google_redirect_uri: String,

    // Future providers can be added here
    // #[serde(default)]
    // pub github_client_id: String,
    // #[serde(default)]
    // pub github_client_secret: String,
    // #[serde(default)]
    // pub github_redirect_uri: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,

    #[serde(default)]
    pub database: DatabaseConfig,

    #[serde(default)]
    pub jwt: JwtConfig,

    #[serde(default)]
    pub oauth: OAuthConfig,
}

pub struct ConfigMetadata {
    pub app_run_env: String,
    pub config_dir: String,
    pub server_address: String,
    pub log_directives: String,
}

pub struct ConfigWithMetadata {
    pub data: Config,
    pub metadata: ConfigMetadata,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 3000,
            log_directives: "info,tower_http=info,axum=info".to_string(),
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
            secret: String::new(),
            access_token_expiry: 15 * 60,             // 15 minutes
            refresh_token_expiry: 200 * 24 * 60 * 60, // 200 days
        }
    }
}

impl Default for OAuthConfig {
    fn default() -> Self {
        Self {
            google_client_id: String::new(),
            google_client_secret: String::new(),
            google_redirect_uri: "http://localhost:3000/auth/oauth/google/callback".to_string(),
        }
    }
}

impl ConfigWithMetadata {
    pub fn new() -> Result<Self, ConfigError> {
        let config_dir = "config".to_string();
        let config_path = Path::new(&config_dir);
        let default_app_run_env = "production".to_string();
        let app_run_env = env::var("APP_RUN_ENV").unwrap_or(default_app_run_env);
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
        let mut config: Config = builder.build()?.try_deserialize().unwrap_or_default();

        // handle JWT secret initialization
        // TODO: probably this should be moved to JwtContext
        config.jwt.secret = Self::ensure_jwt_secret(config_path)?;

        let metadata = ConfigMetadata {
            app_run_env,
            config_dir: config_path
                .canonicalize()
                .ok()
                .map_or(config_dir, |p| p.to_string_lossy().to_string()),
            server_address: format!("{}:{}", config.server.host, config.server.port),
            log_directives: config.server.log_directives.clone(),
        };

        // TODO: write config to file if it doesn't exist, so that it can be modified by users
        // if !env_config_path.exists() {
        //     fs::write(&env_config_path, toml::to_string(&config).unwrap())
        //         .map_err(|e| ConfigError::Message(format!("Failed to write config file: {}", e)))?;
        //     println!("Created default config file at {env_config_path:?}");
        // }

        Ok(Self { data: config, metadata })
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
}
