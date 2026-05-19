use axum::body::Body;
use axum::extract::Request;
use axum::extract::State;
use axum::http::header;
use axum::response::IntoResponse;
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
pub async fn user_info_handler(State(context): State<common::ArcContext>, req: Request<Body>) -> impl IntoResponse {
    let user = auth::decode_token_from_req(&context, &req, auth::TokenType::Access)
        .ok()
        .and_then(|claims| {
            let id = claims.user_id().ok()?;
            Some(User {
                id,
                email: claims.email,
                tenant_id: claims.tenant_id,
            })
        });

    let user_json = user
        .and_then(|u| serde_json::to_string(&u).ok())
        .unwrap_or_else(|| "null".to_string());

    // Define the headers safely as an array of tuples
    let headers = [
        (header::CONTENT_TYPE, "application/javascript"),
        (header::CACHE_CONTROL, "no-cache, no-store, must-revalidate"),
    ];

    // Returning a tuple implicitly builds a 200 OK response safely
    (headers, format!("export const initialUserInfo = {user_json};"))
}
