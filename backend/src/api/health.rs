use axum::{extract::State, response::IntoResponse};
use serde::Serialize;

use crate::common;
use crate::common::ApiError;
use crate::db;

#[derive(Serialize)]
struct HealthCheckResponse {
    message: String,
}

#[allow(clippy::unused_async)]
pub async fn health_check(State(context): State<common::ArcContext>) -> Result<impl IntoResponse, ApiError> {
    // read the tenant from db
    db::get_tenant_by_id(&context.db, 0).await.map_err(|e| {
        tracing::error!("Health check failed to read default tenant from database: {}", e);
        ApiError::internal()
    })?;

    let body = HealthCheckResponse {
        message: "sever and database are up and running".to_string(),
    };
    Ok(axum::response::Json(body))
}
