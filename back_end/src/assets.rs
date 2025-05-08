use axum::{
    body::Body,
    http::{self, header, Response, StatusCode, Uri},
    response::{IntoResponse, Result as AxumResult},
};
use rust_embed::RustEmbed;
use thiserror::Error;
use chrono::{Utc, TimeZone}; // Added for Last-Modified header

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
        tracing::error!("{}", &self);

        let status = match self {
            Self::ResponseBuildError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
        };

        let body = match self {
            Self::ResponseBuildError(_) => "Internal server error".to_string(),
            Self::NotFound(path) => format!("Asset not found: {}", path),
        };

        (status, body).into_response()
    }
}

pub async fn static_handler(uri: Uri) -> AxumResult<impl IntoResponse, AssetError> {
    let mut path_str = uri.path().trim_start_matches('/');
    if path_str.is_empty() {
        path_str = "index.html";
    }

    match Assets::get(path_str) {
        Some(content) => { // Asset found directly
            let mime_type = mime_guess::from_path(path_str).first_or_octet_stream();
            let mut builder = Response::builder()
                .header(header::CONTENT_TYPE, mime_type.as_ref());

            if path_str == "index.html" {
                builder = builder.header(header::CACHE_CONTROL, "no-cache, no-store, must-revalidate");
            } else {
                // Aggressive caching for other assets
                builder = builder.header(header::CACHE_CONTROL, "public, max-age=31536000, immutable"); // 1 year

                let hash_bytes = content.metadata.sha256_hash();
                let hex_hash: String = hash_bytes.iter().map(|b| format!("{:02x}", b)).collect();
                let etag = format!("\"{}\"", hex_hash);
                builder = builder.header(header::ETAG, etag);

                if let Some(last_modified_ts) = content.metadata.last_modified() {
                    if let Some(dt) = Utc.timestamp_opt(last_modified_ts as i64, 0).single() {
                        builder = builder.header(header::LAST_MODIFIED, dt.to_rfc2822());
                    }
                }
            }
            Ok(builder.body(Body::from(content.data.to_vec()))?)
        }
        None => { // Asset not found directly
            // If the requested path was not "index.html", try serving "index.html" as a fallback for SPA routing.
            if path_str != "index.html" {
                if let Some(index_content) = Assets::get("index.html") {
                    return Ok(Response::builder()
                        .header(header::CONTENT_TYPE, "text/html")
                        .header(header::CACHE_CONTROL, "no-cache, no-store, must-revalidate")
                        .body(Body::from(index_content.data.to_vec()))?);
                } else {
                    // Critical error: requested asset not found, AND index.html (SPA fallback) is also missing.
                    return Err(AssetError::NotFound("index.html".to_string()));
                }
            }
            Err(AssetError::NotFound(path_str.to_string()))
        }
    }
}