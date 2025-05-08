use axum::{
    body::Body,
    http::{self, header, Response, StatusCode, Uri},
    response::{IntoResponse, Result as AxumResult},
};
use rust_embed::RustEmbed;
use thiserror::Error;

#[derive(RustEmbed)]
#[folder = "../front_end/dist"]
pub struct Assets;

#[derive(Debug, Error)]
pub enum AssetError {
    #[error("Failed to build response: {0}")]
    ResponseBuildError(#[from] http::Error),

    #[error("Asset not found: {0}")]
    NotFound(String),
}

impl IntoResponse for AssetError {
    fn into_response(self) -> axum::response::Response {
        let status = match self {
            Self::ResponseBuildError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
        };

        let body = match self {
            Self::ResponseBuildError(err) => format!("Internal server error: {}", err),
            Self::NotFound(path) => format!("Asset not found: {}", path),
        };

        (status, body).into_response()
    }
}

pub async fn static_handler(uri: Uri) -> AxumResult<impl IntoResponse, AssetError> {
    let path = uri.path().trim_start_matches('/');

    // If path is empty, serve index.html
    let path = if path.is_empty() { "index.html" } else { path };

    match Assets::get(path) {
        Some(content) => {
            let mime_type = mime_guess::from_path(path).first_or_octet_stream();

            Ok(Response::builder()
                .header(header::CONTENT_TYPE, mime_type.as_ref())
                .body(Body::from(content.data.to_vec()))?)
        }
        None => {
            // Try to serve index.html for client-side routing
            if let Some(content) = Assets::get("index.html") {
                Ok(Response::builder()
                    .header(header::CONTENT_TYPE, "text/html")
                    .body(Body::from(content.data.to_vec()))?)
            } else {
                Err(AssetError::NotFound("index.html".to_string()))
            }
        }
    }
}