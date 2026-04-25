use axum::body::Body;
use axum::extract::Request;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::Response;
use serde_json::json;

use crate::auth;
use crate::core;

/// Handler for providing the initial user info for the frontend as a JS script
pub async fn user_info_handler(
    State(context): State<core::ArcContext>,
    req: Request<Body>,
) -> Result<Response, StatusCode> {
    let state = match auth::decode_token_from_req(&context, &req, auth::TokenType::Access) {
        Ok(claims) => {
            json!({
                "result": "ok",
                "user": {
                    "id": claims.sub,
                    "email": claims.email,
                    "tenant_id": claims.tenant_id
                }
            })
        }
        _ => json!({ "result": "error", "user": null }),
    };
    let body = format!("export const initialUserInfo = {state};");
    Response::builder()
        .header(header::CONTENT_TYPE, "application/javascript")
        .header(header::CACHE_CONTROL, "no-cache, no-store, must-revalidate")
        .body(Body::from(body))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}
