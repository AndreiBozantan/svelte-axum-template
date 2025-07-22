use crate::core::config::Config;
use crate::core::db::DbPoolType;

#[derive(Clone)]
pub struct Context {
    pub db: DbPoolType,
    pub config: Config,
}

pub type ArcContext = std::sync::Arc<Context>;

impl Context {
    pub fn new(db: DbPoolType, config: Config) -> Self {
        Self {db, config}
    }
}
