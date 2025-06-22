use std::{fs, path::Path};
use config::{Config, ConfigError, Environment, File};
use serde::Deserialize;

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

    #[serde(default)]
    pub run_db_migrations_on_startup: bool,
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
            log_directives: "svelte_axum_template=debug,tower_http=info".to_string(),
        }
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: "sqlite:db.sqlite".to_string(),
            max_connections: 5,
            run_db_migrations_on_startup: true, // default to true for development
        }
    }
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            secret: "".to_string(),
            access_token_expiry: 15 * 60,             // 15 minutes
            refresh_token_expiry: 200 * 24 * 60 * 60, // 200 days
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

        // TODO: move config to yml files
        // TODO: check if the configs are loaded correctly in dev mode, when using `cargo run`

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
        let mut config: AppConfig = builder
            .build()?
            .try_deserialize()
            .unwrap_or_default();

        // handle JWT secret initialization
        config.jwt.secret = Self::ensure_jwt_secret()?;

        // TODO: write config to file if it doesn't exist


        Ok(config)
    }

    fn ensure_jwt_secret() -> Result<String, ConfigError> {
        // Priority 1: Check environment variable
        if let Ok(env_secret) = std::env::var("APP_JWT_SECRET") {
            if !env_secret.is_empty() && env_secret.len() >= 32 {
                return Ok(env_secret);
            }
        }

        // Priority 2: Check persisted secret file
        let secret_file_path = "./config/.jwt_secret";
        if let Ok(file_secret) = fs::read_to_string(secret_file_path) {
            let trimmed_secret = file_secret.trim();
            if !trimmed_secret.is_empty() && trimmed_secret.len() >= 32 {
                return Ok(trimmed_secret.to_string());
            }
        }

        // Priority 3: Generate new secret and persist it
        let new_secret = Self::generate_secure_secret();

        // Create config directory if it doesn't exist
        if let Some(parent) = Path::new(secret_file_path).parent() {
            fs::create_dir_all(parent).map_err(|e| {
                ConfigError::Message(format!("Failed to create config directory: {}", e))
            })?;
        }

        // Write the secret to file with restricted permissions
        fs::write(secret_file_path, &new_secret).map_err(|e| {
            ConfigError::Message(format!("Failed to write JWT secret to file: {}", e))
        })?;

        // Set file permissions to be readable only by owner (Unix-like systems)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(secret_file_path)
                .map_err(|e| ConfigError::Message(format!("Failed to get file metadata: {}", e)))?
                .permissions();
            perms.set_mode(0o600); // rw-------
            fs::set_permissions(secret_file_path, perms)
                .map_err(|e| ConfigError::Message(format!("Failed to set file permissions: {}", e)))?;
        }

        println!("Generated new JWT secret and saved to {}", secret_file_path);
        Ok(new_secret)
    }

    fn generate_secure_secret() -> String {
        use rand::Rng;
        let random_bytes: [u8; 32] = rand::rng().random();
        hex::encode(random_bytes)
    }
}
