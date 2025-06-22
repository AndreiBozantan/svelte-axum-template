use std::sync::Arc;

use crate::app;
use crate::db;

#[derive(Clone)]
pub struct Context {
    pub store: Arc<db::Store>,
    pub config: Arc<app::Config>,
}

impl Context {
    pub async fn new(config: app::Config) -> Result<Self, db::DbError> {
        let db_pool = db::init_pool(&config.database).await?;
        Ok(Self {
            store: Arc::new(db::Store::new(db_pool)),
            config: Arc::new(config),
        })
    }
}
