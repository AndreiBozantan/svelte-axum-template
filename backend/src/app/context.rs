use std::sync::Arc;

use crate::app;
use crate::db;

#[derive(Clone)]
pub struct Context {
    pub store: Arc<db::Store>,
    pub config: Arc<app::Config>,
}

impl Context {
    pub async fn new(config: app::Config) -> Result<Self, db::StoreError> {
        let store = db::Store::new(&config.database).await?;
        Ok(Self {
            config: Arc::new(config),
            store: Arc::new(store),
        })
    }
}
