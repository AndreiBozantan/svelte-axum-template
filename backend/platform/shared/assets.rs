use axum::body::Body;
use axum::http;
use axum::http::Uri;
use axum::http::header;
use axum::response::IntoResponse;
use axum::response::Response;
use chrono::TimeZone;
use chrono::Utc;
use rust_embed::RustEmbed;

use crate::platform::api;

#[derive(RustEmbed)]
#[folder = "../frontend/dist"]
struct Assets;

#[allow(clippy::unused_async)]
pub async fn static_handler(
    uri: Uri,
    headers: http::HeaderMap,
) -> Result<impl IntoResponse, api::Error> {
    let path_str = uri.path().trim_start_matches('/');
    let path_str = if path_str.is_empty() { "index.html" } else { path_str };
    let asset = Assets::get(path_str);
    let path_str = if asset.is_none() { "index.html" } else { path_str };
    let asset = asset
        .or_else(|| Assets::get(path_str))
        .ok_or_else(api::Error::not_found)?;

    let etag = hex::encode(asset.metadata.sha256_hash());

    // check If-None-Match header for client caching (304 Not Modified)
    if headers
        .get(header::IF_NONE_MATCH)
        .and_then(|val| val.to_str().ok())
        .is_some_and(|s| s.trim_matches('"') == etag)
    {
        return Ok(http::StatusCode::NOT_MODIFIED.into_response());
    }

    let builder = match path_str {
        "index.html" => create_index_response_builder(&asset, &etag),
        _ => create_asset_response_builder(&asset, path_str, &etag),
    };
    let body = builder.body(Body::from(asset.data.to_vec()))?;
    Ok(body.into_response())
}

type Builder = http::response::Builder;

fn create_index_response_builder(
    _asset: &rust_embed::EmbeddedFile,
    etag: &str,
) -> Builder {
    Response::builder()
        .header(header::CONTENT_TYPE, "text/html")
        .header(header::CACHE_CONTROL, "no-cache")
        .header(header::ETAG, etag)
}

fn create_asset_response_builder(
    asset: &rust_embed::EmbeddedFile,
    path: &str,
    etag: &str,
) -> Builder {
    let mime_type = mime_guess::from_path(path).first_or_octet_stream();
    let builder = Response::builder()
        .header(header::CONTENT_TYPE, mime_type.as_ref())
        .header(header::CACHE_CONTROL, "public, max-age=31536000, immutable")
        .header(header::ETAG, etag);
    match asset_last_modified(asset) {
        Some(last_modified) => builder.header(header::LAST_MODIFIED, last_modified),
        None => builder,
    }
}

#[allow(clippy::cast_possible_wrap)]
fn asset_last_modified(asset: &rust_embed::EmbeddedFile) -> Option<String> {
    asset
        .metadata
        .last_modified()
        .and_then(|ts| Utc.timestamp_opt(ts as i64, 0).single())
        .map(|dt| dt.to_rfc2822())
}
