use crate::auth;
use crate::cfg;
use crate::cfg::AppSettings;
use crate::db;

pub type ArcContext = std::sync::Arc<Context>;

#[derive(Clone)]
pub struct Context {
    pub env: String,
    pub db: db::SqlContext,
    pub jwt: auth::JwtContext,
    pub settings: cfg::AppSettings,
    pub http_client: reqwest::Client,
}

impl Context {
    #[must_use]
    pub fn new(
        db: db::SqlContext,
        jwt: auth::JwtContext,
        settings: cfg::AppSettings,
        http_client: reqwest::Client,
    ) -> ArcContext {
        let env = AppSettings::get_app_run_env(&settings.server.env_vars_prefix);
        Self {
            env,
            db,
            jwt,
            settings,
            http_client,
        }
        .into()
    }
}
