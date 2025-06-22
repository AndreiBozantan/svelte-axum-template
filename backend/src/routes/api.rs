use axum::{extract::State, response::IntoResponse, Json};
use serde_json::json;

use crate::app;

/// imitating an API response
#[allow(clippy::unused_async)]
pub async fn handler(State(_context): State<app::Context>) -> impl IntoResponse {
    tracing::info!("Seeking api data");
    Json(
        json!({"result": "ok", "message": "You've reached the backend API by using a valid token."}),
    )
}
