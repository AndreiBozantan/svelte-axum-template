use axum::body::Body;
use axum::extract::Request;
use axum::http;
use axum::response::IntoResponse;
use axum::response::Response;
use serde::Serialize;
use sha2::Digest;
use thiserror::Error;

use crate::api;
use crate::common;
use crate::internal::logger;
use crate::jwt;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Invalid header value: {0}")]
    InvalidHeaderValue(#[from] http::header::InvalidHeaderValue),

    #[error("JWT operation failed: {0}")]
    JwtOperationFailed(#[from] jwt::Error),

    #[error("Token expired or invalid")]
    InvalidToken,
}

impl From<Error> for api::Error {
    fn from(error: Error) -> Self {
        logger::log_auth_rejection(&error);
        match error {
            Error::JwtOperationFailed(jwt::Error::ExpiredToken) => Self::expired_token(),
            _ => Self::invalid_token(),
        }
    }
}

#[must_use]
pub fn get_token_hash_as_hex(token: &str) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(token);
    hex::encode(hasher.finalize())
}

pub fn decode_token_from_req(
    context: &common::ArcContext,
    req: &Request,
    token_type: jwt::TokenType,
) -> Result<jwt::TokenClaims, Error> {
    let token = get_cookie_value_from_headers(req.headers(), "access_token")
        .map_or_else(|| extract_bearer_token(req), Ok)?; // fallback to Authorization: Bearer for API clients
    let claims = jwt::decode_token(&context.jwt, token, token_type)?;
    Ok(claims)
}

fn extract_bearer_token(req: &Request<Body>) -> Result<&str, Error> {
    req.headers()
        .get(http::header::AUTHORIZATION)
        .ok_or(Error::InvalidToken)?
        .to_str()
        .map_err(|_| Error::InvalidToken)?
        .strip_prefix("Bearer ")
        .ok_or(Error::InvalidToken)
}

pub fn get_refresh_token_from_cookie(req: &Request<Body>) -> Result<&str, Error> {
    get_cookie_value_from_headers(req.headers(), "refresh_token").ok_or(Error::InvalidToken)
}

pub fn add_auth_cookies(
    context: &common::ArcContext,
    response: Response<Body>,
    access_token: Option<&str>,
    refresh_token: Option<&str>,
) -> Result<Response<Body>, Error> {
    let mut response = response;
    let headers = response.headers_mut();

    // access token (default to empty string with Max-Age=0 to clear it if None)
    let at_val = access_token.unwrap_or("");
    let access_max_age = context.settings.jwt.access_token_expiry_minutes * 60;
    let access_cookie = create_token_cookie("access_token", at_val, "/", access_max_age);
    headers.append(http::header::SET_COOKIE, access_cookie.parse()?);

    // refresh token (default to empty string with Max-Age=0 to clear it if None)
    let rt_val = refresh_token.unwrap_or("");
    let refresh_max_age = context.settings.jwt.refresh_token_expiry_days * 60 * 60 * 24;
    let refresh_cookie = create_token_cookie("refresh_token", rt_val, "/api/auth/", refresh_max_age);
    headers.append(http::header::SET_COOKIE, refresh_cookie.parse()?);

    Ok(response)
}

/// Build a JSON response and attach auth cookies in one step.
pub fn create_response_with_auth_cookies(
    context: &common::ArcContext,
    body: &impl Serialize,
    access_token: Option<&str>,
    refresh_token: Option<&str>,
) -> Result<Response<Body>, Error> {
    let response = axum::response::Json(body).into_response();
    add_auth_cookies(context, response, access_token, refresh_token)
}

pub fn get_cookie_value_from_headers<'a>(headers: &'a http::HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(http::header::COOKIE)
        .and_then(|header| header.to_str().ok())
        .and_then(|cookie_str| extract_token_from_cookie(cookie_str, name))
}

#[must_use]
pub fn extract_token_from_cookie<'a>(cookie_str: &'a str, token_name: &str) -> Option<&'a str> {
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
    let max_age = if cookie_value.is_empty() { 0 } else { max_age };
    format!("{cookie_name}={cookie_value}; HttpOnly; Secure; SameSite=Strict; Path={path}; Max-Age={max_age}")
}
