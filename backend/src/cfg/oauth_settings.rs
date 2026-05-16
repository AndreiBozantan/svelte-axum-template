use serde::{Deserialize, Serialize};

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
            google_redirect_uri: "http://localhost:3000/oauth/google/callback".to_string(),
            session_timeout_minutes: default_session_timeout(),
        }
    }
}
