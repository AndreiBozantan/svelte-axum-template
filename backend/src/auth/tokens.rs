use axum::body::Body;
use axum::extract::Request;
use axum::http;
use axum::response::IntoResponse;
use axum::response::Response;
use sha2::Digest;
use thiserror::Error;

use crate::auth;
use crate::core;

#[derive(Debug, Error)]
pub enum TokenError {
    #[error("Invalid header value: {0}")]
    InvalidHeaderValue(#[from] reqwest::header::InvalidHeaderValue),

    #[error("JWT operation failed: {0}")]
    JwtOperationFailed(#[from] auth::JwtError),

    #[error("Token expired or invalid")]
    TokenInvalid,
}

pub fn get_token_hash_as_hex(token: &str) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(token);
    format!("{:x}", hasher.finalize())
}

pub fn decode_token_from_req(
    context: &core::ArcContext,
    req: &Request,
    token_type: auth::TokenType,
) -> Result<auth::TokenClaims, TokenError> {
    req.headers()
        .get(http::header::COOKIE) // attempt to extract token from the Cookie header first
        .and_then(|header| header.to_str().ok())
        .and_then(|cookie| extract_token_from_cookie(cookie, "access_token"))
        .map(Ok)
        .unwrap_or_else(|| extract_bearer_token(req)) // fallback to Bearer token
        .and_then(|token| auth::decode_token(&context.jwt, token, token_type).map_err(TokenError::from))
}

fn extract_bearer_token(req: &Request<Body>) -> Result<&str, TokenError> {
    req.headers()
        .get(http::header::AUTHORIZATION)
        .ok_or(TokenError::TokenInvalid)?
        .to_str()
        .map_err(|_| TokenError::TokenInvalid)?
        .strip_prefix("Bearer ")
        .ok_or(TokenError::TokenInvalid)
}

pub fn get_refresh_token_from_cookie(req: &Request<Body>) -> Result<&str, TokenError> {
    req.headers()
        .get(reqwest::header::COOKIE)
        .and_then(|header| header.to_str().ok())
        .and_then(|cookie_str| extract_token_from_cookie(cookie_str, "refresh_token"))
        .ok_or(TokenError::TokenInvalid)
}

pub fn add_auth_cookies(
    context: &core::ArcContext,
    access_token: &Option<&str>,
    refresh_token: &Option<&str>,
    response: Response<Body>,
) -> Result<Response<Body>, TokenError> {
    let mut response = response;
    let headers = response.headers_mut();
    if let Some(at) = access_token {
        let access_max_age = context.settings.jwt.access_token_expiry_minutes * 60;
        let access_cookie = create_token_cookie("access_token", at, "/", access_max_age);
        headers.append(reqwest::header::SET_COOKIE, access_cookie.parse()?);
    }
    if let Some(rt) = refresh_token {
        let refresh_max_age = context.settings.jwt.refresh_token_expiry_days * 60 * 60 * 24;
        let refresh_cookie = create_token_cookie("refresh_token", rt, "/api/auth/refresh", refresh_max_age);
        headers.append(reqwest::header::SET_COOKIE, refresh_cookie.parse()?);
    }
    Ok(response)
}

pub fn create_json_response_with_auth_cookies(
    context: &core::ArcContext,
    access_token: &Option<&str>,
    refresh_token: &Option<&str>,
    json: serde_json::Value,
) -> Result<Response<Body>, TokenError> {
    let response = axum::response::Json(json).into_response();
    add_auth_cookies(context, access_token, refresh_token, response)
}

fn extract_token_from_cookie<'a>(cookie_str: &'a str, token_name: &str) -> Option<&'a str> {
    cookie_str.split(';').find_map(|cookie| {
        let mut parts = cookie.trim().splitn(2, '=');
        if parts.next()? == token_name {
            parts.next()
        } else {
            None
        }
    })
}

fn create_token_cookie(cookie_name: &str, cookie_value: &str, path: &str, max_age: u32) -> String {
    let max_age = match cookie_value {
        "" => 0,
        _ => max_age,
    };
    format!(
        "{}={}; HttpOnly; Secure; SameSite=Strict; Path={}; Max-Age={}",
        cookie_name, cookie_value, path, max_age
    )
}
