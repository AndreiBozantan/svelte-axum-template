use std::fmt::Write as _;

use axum::body::Body;
use axum::http;
use axum::http::response::Builder as ResponseBuilder;
use axum::http::Uri;
use axum::http::header;
use axum::response::IntoResponse;
use axum::response::Response;
use axum::response::Result;
use chrono::{TimeZone, Utc};
use rust_embed::EmbeddedFile;
use rust_embed::RustEmbed;
use thiserror::Error;

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
            Self::NotFound(path) => format!("Asset not found: {path}"),
        };

        (status, body).into_response()
    }
}

pub async fn static_handler(uri: Uri) -> Result<impl IntoResponse, AssetError> {
    let path_str = uri.path().trim_start_matches('/');
    let path_str = if path_str.is_empty() { "index.html" } else { path_str };
    let asset = Assets::get(path_str)
        .or_else(|| {
            tracing::info!("Falling back to index.html for path: {}", path_str);
            Assets::get("index.html")
        })
        .ok_or_else(|| AssetError::NotFound(path_str.to_string()))?;
    let builder = match path_str {
        "index.html" => create_no_cache_response_builder(),
        _ => create_asset_response_builder(&asset, path_str),
    };
    Ok(builder.body(Body::from(asset.data.to_vec()))?)
}

fn create_no_cache_response_builder() -> ResponseBuilder {
    Response::builder()
        .header(header::CONTENT_TYPE, "text/html")
        .header(header::CACHE_CONTROL, "no-cache, no-store, must-revalidate")
}

fn create_asset_response_builder(asset: &EmbeddedFile, path: &str) -> ResponseBuilder {
    let mime_type = mime_guess::from_path(path).first_or_octet_stream();
    let etag = hex::encode(asset.metadata.sha256_hash());
    let builder = Response::builder()
        .header(header::CONTENT_TYPE, mime_type.as_ref())
        .header(header::CACHE_CONTROL, "public, max-age=31536000, immutable")
        .header(header::ETAG, etag);
    match get_asset_last_modified_date(asset) {
        Some(last_modified) => builder.header(header::LAST_MODIFIED, last_modified),
        None => builder,
    }
}

#[allow(clippy::cast_possible_wrap)] // the timestamp will be in the range of i64 for quite some time
fn get_asset_last_modified_date(asset: &EmbeddedFile) -> Option<String> {
    asset.metadata.last_modified()
        .and_then(|ts| Utc.timestamp_opt(ts as i64, 0).single())
        .map(|dt| dt.to_rfc2822())
}