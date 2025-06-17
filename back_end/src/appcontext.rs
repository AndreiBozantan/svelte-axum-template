use std::sync::Arc;
use crate::appconfig::AppConfig;
use crate::db::DbPool;
use crate::store::Store;

#[derive(Clone)]
pub struct AppContext {
    pub store: Arc<Store>,
    pub config: Arc<AppConfig>,
}

impl AppContext {
    pub fn new(db_pool: DbPool, config: AppConfig) -> Self {
        Self {
            store: Arc::new(Store::new(db_pool)),
            config: Arc::new(config),
        }
    }
}
