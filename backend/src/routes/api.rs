use axum::{Json, extract::State, response::IntoResponse};
use serde_json::json;

use crate::core;

/// imitating an API response
#[allow(clippy::unused_async)]
pub async fn test_handler(State(_context): State<core::ArcContext>) -> impl IntoResponse {
    // sleep to simulate some processing and return a JSON response
    std::thread::sleep(std::time::Duration::from_millis(1200));
    tracing::info!("Seeking api data");
    let time = chrono::Utc::now().to_rfc3339();
    Json(json!({"result": "ok", "message": format!("You've reached the backend API by using a valid token at {time}.")}))
}
