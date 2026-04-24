use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde_json::json;

use crate::core;
use crate::db;

#[allow(clippy::unused_async)]
pub async fn health_check(
    State(context): State<core::ArcContext>,
) -> Result<impl IntoResponse, axum::response::Response> {
    // read the tenant from db
    db::get_tenant_by_id(&context.db, 0).await.map_err(|e| {
        tracing::error!("Health check failed to read default tenant from database: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"result": "error", "message": "Internal Server Error"})),
        )
            .into_response()
    })?;

    Ok((StatusCode::OK, Json(json!({"result": "ok", "message": "OK"}))))
}
