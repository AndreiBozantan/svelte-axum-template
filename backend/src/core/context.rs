use crate::auth;
use crate::cfg;
use crate::core;
use crate::services::sso;

pub type ArcContext = std::sync::Arc<Context>;

#[derive(Clone)]
pub struct Context {
    pub db: core::DbContext,
    pub jwt: auth::JwtContext,
    pub settings: cfg::AppSettings,
    pub http_client: reqwest::Client,
    pub oauth_session_store: sso::OAuthSessionStore,
}

impl Context {
    #[must_use]
    pub fn new(
        db: core::DbContext,
        jwt: auth::JwtContext,
        http_client: reqwest::Client,
        settings: cfg::AppSettings,
    ) -> ArcContext {
        Self {
            db,
            jwt,
            settings,
            http_client,
            oauth_session_store: sso::create_oauth_session_store(),
        }
        .into()
    }
}
