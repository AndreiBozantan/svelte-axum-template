use axum::{extract::State, response::IntoResponse};
use serde::Serialize;

use crate::common;

#[derive(Serialize)]
struct TestResponse {
    message: String,
}

/// imitating an API response
#[allow(clippy::unused_async)]
pub async fn test_handler(State(_context): State<common::ArcContext>) -> impl IntoResponse {
    // sleep to simulate some processing and return a JSON response
    std::thread::sleep(std::time::Duration::from_millis(1200));
    let time = chrono::Utc::now().to_rfc3339();
    let body = TestResponse {
        message: format!("Successful API request at {time}."),
    };
    axum::response::Json(body)
}
