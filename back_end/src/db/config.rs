use dotenv::dotenv;
use std::env;

#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    pub database_url: String,
    pub max_connections: u32,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            database_url: "sqlite:db.sqlite".to_string(),
            max_connections: 5,
        }
    }
}

impl DatabaseConfig {
    pub fn from_env() -> Self {
        dotenv().ok(); // Load environment variables from .env file if available

        Self {
            database_url: env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite:db.sqlite".to_string()),
            max_connections: env::var("DATABASE_MAX_CONNECTIONS")
                .ok()
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(5),
        }
    }
}