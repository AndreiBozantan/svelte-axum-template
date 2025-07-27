use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct JwtSettings {
    #[serde(default)]
    pub secret: String, // TODO: should this be removed from here?

    #[serde(default)]
    pub access_token_expiry: i64, // In seconds (e.g., 15 minutes = 900)

    #[serde(default)]
    pub refresh_token_expiry: i64, // In seconds (e.g., 7 days = 604800)
}

impl Default for JwtSettings {
    fn default() -> Self {
        Self {
            secret: String::new(),
            access_token_expiry: 15 * 60,             // 15 minutes
            refresh_token_expiry: 200 * 24 * 60 * 60, // 200 days
        }
    }
}

