use axum::body::Body;
use axum::http;
use axum::http::Uri;
use axum::http::header;
use axum::response::IntoResponse;
use axum::response::Result;
use axum::response::Response;
use rust_embed::RustEmbed;
use thiserror::Error;
use chrono::{Utc, TimeZone};

#[derive(RustEmbed)]
#[folder = "../frontend/dist"]
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
            Self::ResponseBuildError(_) => http::StatusCode::INTERNAL_SERVER_ERROR,
            Self::NotFound(_) => http::StatusCode::NOT_FOUND,
        };

        let body = match self {
            Self::ResponseBuildError(_) => "Internal server error".to_string(),
            Self::NotFound(path) => format!("Asset not found: {}", path),
        };

        return (status, body).into_response();
    }
}

pub async fn static_handler(uri: Uri) -> Result<impl IntoResponse, AssetError> {
    let mut path_str = uri.path().trim_start_matches('/');
    if path_str.is_empty() {
        path_str = "index.html";
    }

    let asset = Assets::get(path_str);
    if asset.is_none() {
        let asset = Assets::get("index.html");
        if asset.is_none() {
            // Critical error: requested asset not found, AND index.html (SPA fallback) is also missing.
            return Err(AssetError::NotFound(path_str.to_string()));
        }

        let index_content = asset.unwrap(); // index.html found
        let response = Response::builder()
            .header(header::CONTENT_TYPE, "text/html")
            .header(header::CACHE_CONTROL, "no-cache, no-store, must-revalidate")
            .body(Body::from(index_content.data.to_vec()))?;

        return Ok(response);
    }

    let content = asset.unwrap(); // Asset found directly
    let mime_type = mime_guess::from_path(path_str).first_or_octet_stream();
    let mut builder = Response::builder().header(header::CONTENT_TYPE, mime_type.as_ref());

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
    return Ok(builder.body(Body::from(content.data.to_vec()))?);
}