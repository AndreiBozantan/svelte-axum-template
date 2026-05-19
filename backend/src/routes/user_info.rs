use axum::body::Body;
use axum::extract::Request;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use axum::response::Response;
use serde::Serialize;

use crate::auth;
use crate::common;

#[derive(Serialize)]
struct User {
    pub id: i64,
    pub email: String,
    pub tenant_id: i64,
}

/// Handler for providing the initial user info for the frontend as a JS script
pub async fn user_info_handler(
    State(context): State<common::ArcContext>,
    req: Request<Body>,
) -> Result<impl IntoResponse, StatusCode> {
    let claims = auth::decode_token_from_req(&context, &req, auth::TokenType::Access)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let user_id = claims.user_id().map_err(|_| StatusCode::UNAUTHORIZED)?;
    let user = User {
        id: user_id,
        email: claims.email,
        tenant_id: claims.tenant_id,
    };
    let json = serde_json::json!(user);
    let body = format!("export const initialUserInfo = {json};");
    Response::builder()
        .header(header::CONTENT_TYPE, "application/javascript")
        .header(header::CACHE_CONTROL, "no-cache, no-store, must-revalidate")
        .body(Body::from(body))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}
