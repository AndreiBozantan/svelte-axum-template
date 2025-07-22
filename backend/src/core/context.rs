use crate::core::config::Config;
use crate::core::dbpool::DbPoolType;

#[derive(Clone)]
pub struct Context {
    pub db: DbPoolType,
    pub config: Config,
    pub http_client: reqwest::Client,
}

pub type ArcContext = std::sync::Arc<Context>;

impl Context {
    pub fn new(db: DbPoolType, config: Config) -> Self {
        let http_client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("Failed to create HTTP client");

        Self {db, config, http_client}
    }
}
