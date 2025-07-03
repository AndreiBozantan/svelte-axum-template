use std::sync::Arc;

use crate::app::{self, db};

#[derive(Clone)]
pub struct Context {
    pub db: Arc<app::Database>,
    pub config: Arc<app::Config>,
}

impl Context {
    pub async fn new(config: app::Config) -> Result<Self, db::DbError> {
        let db = app::Database::new(&config.database).await?;
        Ok(Self {
            config: Arc::new(config),
            db: Arc::new(db),
        })
    }
}
