use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct DatabaseSettings {
    #[serde(default)]
    pub url: String,

    #[serde(default)]
    pub max_connections: u32,
}

impl Default for DatabaseSettings {
    fn default() -> Self {
        Self {
            url: "sqlite:db.sqlite".to_string(),
            max_connections: 5,
        }
    }
}

