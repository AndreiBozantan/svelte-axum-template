use axum::{extract::State, response::IntoResponse};
use serde::Serialize;

use crate::platform::common::ArcContext;
use crate::platform::common::ApiError;

use crate::app::identity::identity_store;

#[derive(Serialize)]
struct HealthCheckResponse {
    message: String,
}

#[allow(clippy::unused_async)]
pub async fn health_check(State(context): State<ArcContext>) -> Result<impl IntoResponse, ApiError> {
    // read the tenant from db
    identity_store::get_tenant_by_id(&context.db, 0).await.map_err(|e| {
        tracing::error!("Health check failed to read default tenant from database: {}", e);
        ApiError::internal()
    })?;

    let time = chrono::Utc::now().to_rfc3339();
    let body = HealthCheckResponse {
        message: format!("sever and database are up and running at {time}"),
    };
    Ok(axum::response::Json(body))
}
