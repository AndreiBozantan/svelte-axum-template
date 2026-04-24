use axum::body::Body;
use axum::extract::State;
use axum::http;
use axum::http::Request;
use axum::http::header;
use axum::http::response::Builder as ResponseBuilder;
use axum::response::IntoResponse;
use axum::response::Response;
use axum::response::Result;
use chrono::{TimeZone, Utc};
use rust_embed::EmbeddedFile;
use rust_embed::RustEmbed;
use thiserror::Error;

use crate::auth;
use crate::core;

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

pub async fn static_handler(
    State(context): State<core::ArcContext>,
    req: Request<Body>,
) -> Result<Response, AssetError> {
    let uri = req.uri().clone();
    let path_str = uri.path().trim_start_matches('/');
    let path_str = if path_str.is_empty() { "index.html" } else { path_str };
    let asset = Assets::get(path_str);
    let path_str = if asset.is_none() { "index.html" } else { path_str };
    let asset = asset
        .or_else(|| Assets::get(path_str))
        .ok_or_else(|| AssetError::NotFound(path_str.to_string()))?;

    if path_str == "index.html" {
        let mut html = String::from_utf8_lossy(&asset.data).to_string();

        // attempt to get session info to inject
        if let Ok(claims) = auth::decode_token_from_req(&context, &req, auth::TokenType::Access) {
            let initial_state = serde_json::json!({
                "user": {
                    "id": claims.sub, 
                    "email": claims.email,
                    "tenant_id": claims.tenant_id
                }
            });

            if let Ok(state_json) = serde_json::to_string(&initial_state) {
                let script = format!(
                    "<script>window.__INITIAL_STATE__ = {state_json};</script>"
                );
                // inject before </head> or <body>
                if let Some(pos) = html.find("</head>") {
                    html.insert_str(pos, &script);
                } else if let Some(pos) = html.find("<body>") {
                    html.insert_str(pos + 6, &script);
                } else {
                    html.push_str(&script);
                }
            }
        }

        let builder = create_no_cache_response_builder();
        return Ok(builder.body(Body::from(html))?.into_response());
    }

    let builder = create_asset_response_builder(&asset, path_str);
    Ok(builder.body(Body::from(asset.data.to_vec()))?.into_response())
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
    asset
        .metadata
        .last_modified()
        .and_then(|ts| Utc.timestamp_opt(ts as i64, 0).single())
        .map(|dt| dt.to_rfc2822())
}
