use axum::{Json, extract::State, response::IntoResponse};
use serde_json::json;

use crate::core;

/// imitating an API response
#[allow(clippy::unused_async)]
pub async fn handler(State(_context): State<core::ArcContext>) -> impl IntoResponse {
    tracing::info!("Seeking api data");
    Json(json!({"result": "ok", "message": "You've reached the backend API by using a valid token."}))
}
