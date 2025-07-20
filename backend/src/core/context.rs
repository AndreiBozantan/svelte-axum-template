use crate::core::config::Config;
use crate::core::db::DbPoolType;

#[derive(Clone)]
pub struct Context {
    pub db: DbPoolType,
    pub config: Config,
}
