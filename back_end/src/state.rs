use std::sync::Arc;
use crate::jwt::JwtConfig;
use crate::store::Store;

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Store>,
    pub jwt_config: Arc<JwtConfig>,
}

impl AppState {
    pub fn new(store: Arc<Store>, jwt_config: Arc<JwtConfig>) -> Self {
        Self { store, jwt_config }
    }
}
