use axum::Json;
use axum::Router;
use serde::Serialize;

use crate::platform::common::ArcContext;

#[derive(Serialize)]
pub struct SampleResponse {
    pub status: String,
    pub data: String,
}

#[allow(clippy::unused_async)]
pub async fn get_sample() -> Json<SampleResponse> {
    Json(SampleResponse {
        status: "success".to_string(),
        data: "Hello from the new app API!".to_string(),
    })
}

pub fn router() -> Router<ArcContext> {
    Router::new().route("/sample", axum::routing::get(get_sample))
}
