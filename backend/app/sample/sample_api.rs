use axum::Json;
use serde::Serialize;
use utoipax;

use crate::platform::common::ArcContext;

pub fn router() -> utoipax::router::OpenApiRouter<ArcContext> {
    utoipax::router::OpenApiRouter::new().routes(utoipax::routes!(get_sample))
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct SampleResponse {
    pub status: String,
    pub data: String,
}

#[allow(clippy::unused_async)]
#[utoipa::path(
    get,
    path = "/api/sample",
    responses(
        (status = 200, description = "Sample response", body = SampleResponse)
    )
)]
pub async fn get_sample() -> Json<SampleResponse> {
    Json(SampleResponse {
        status: "success".to_string(),
        data: "Hello from the new app API!".to_string(),
    })
}
