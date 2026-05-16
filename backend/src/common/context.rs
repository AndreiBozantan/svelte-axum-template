use crate::auth;
use crate::cfg;
use crate::db;

pub type ArcContext = std::sync::Arc<Context>;

#[derive(Clone)]
pub struct Context {
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
        http_client: reqwest::Client,
        settings: cfg::AppSettings,
    ) -> ArcContext {
        Self {
            db,
            jwt,
            settings,
            http_client,
        }
        .into()
    }
}
