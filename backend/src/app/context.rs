use std::sync::Arc;

use crate::app;
use crate::core;

#[derive(Clone)]
pub struct Context {
    pub db: Arc<app::Database>,
    pub config: Arc<core::Config>,
}

impl Context {
    pub async fn new(config: core::Config) -> Result<Self, app::db::DbError> {
        let db = app::Database::new(&config.database).await?;
        Ok(Self {
            config: Arc::new(config),
            db: Arc::new(db),
        })
    }
}
