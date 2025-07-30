use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OAuthSettings {
    #[serde(default)]
    pub google_client_id: String,

    #[serde(default)]
    pub google_client_secret: String,

    #[serde(default)]
    pub google_redirect_uri: String,

    /// Allowed redirect domains for OAuth callbacks (security)
    #[serde(default)]
    pub allowed_redirect_domains: Vec<String>,

    /// Session timeout in minutes for OAuth flow
    #[serde(default = "default_session_timeout")]
    pub session_timeout_minutes: u64,
}

fn default_session_timeout() -> u64 {
    10 // 10 minutes default
}

impl Default for OAuthSettings {
    fn default() -> Self {
        Self {
            google_client_id: String::new(),
            google_client_secret: String::new(),
            google_redirect_uri: "http://localhost:3000/auth/oauth/google/callback".to_string(),
            allowed_redirect_domains: vec![
                "localhost".to_string(),
                "127.0.0.1".to_string(),
                // Add your production domain here: "yourdomain.com".to_string(),
            ],
            session_timeout_minutes: default_session_timeout(),
        }
    }
}
