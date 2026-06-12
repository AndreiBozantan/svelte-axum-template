use axum::body::Body;
use axum::http;
use axum::response::IntoResponse;
use axum::response::Response;
use axum_extra::extract::cookie::Cookie;
use axum_extra::extract::cookie::CookieJar;
use axum_extra::extract::cookie::SameSite;
use cookie::time::Duration;
use serde::Serialize;
use thiserror::Error;

use crate::platform::api;
use crate::platform::config;
use crate::platform::jwt;
use crate::platform::logger;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid header value: {0}")]
    InvalidHeaderValue(#[from] http::header::InvalidHeaderValue),

    #[error("jwt operation failed: {0}")]
    JwtOperationFailed(#[from] jwt::Error),

    #[error("token expired or invalid")]
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

pub fn decode_access_token_from_cookie(
    context: &jwt::Context,
    headers: &http::HeaderMap,
) -> Result<jwt::TokenClaims, Error> {
    // check cookie first with fallback to bearer token
    let jar = CookieJar::from_headers(headers);
    let token = jar
        .get("access_token")
        .map(Cookie::value)
        .ok_or(Error::InvalidToken)
        .or_else(|_| extract_bearer_token(headers))?;
    Ok(jwt::decode_token(context, token, jwt::TokenType::Access)?)
}

pub fn get_refresh_token_from_cookie(headers: &http::HeaderMap) -> Result<String, Error> {
    CookieJar::from_headers(headers)
        .get("refresh_token")
        .map(|c| c.value().to_string())
        .ok_or(Error::InvalidToken)
}

pub fn add_auth_cookies(
    settings: &config::JwtSettings,
    response: Response<Body>,
    access_token: Option<&str>,
    refresh_token: Option<&str>,
) -> Result<Response<Body>, Error> {
    let at_cookie = create_token_cookie(
        "access_token",
        access_token,
        "/",
        Duration::minutes(i64::from(settings.access_token_expiry_minutes)),
    );

    let rt_cookie = create_token_cookie(
        "refresh_token",
        refresh_token,
        "/api/auth/",
        Duration::days(i64::from(settings.refresh_token_expiry_days)),
    );

    let mut jar = CookieJar::new();
    jar = jar.add(at_cookie).add(rt_cookie);

    let mut response = response;
    let headers = response.headers_mut();
    for cookie in jar.iter() {
        headers.append(http::header::SET_COOKIE, cookie.to_string().parse()?);
    }

    Ok(response)
}

pub fn create_response_with_auth_cookies(
    settings: &config::JwtSettings,
    body: &impl Serialize,
    access_token: Option<&str>,
    refresh_token: Option<&str>,
) -> Result<Response<Body>, Error> {
    let response = axum::response::Json(body).into_response();
    add_auth_cookies(settings, response, access_token, refresh_token)
}

pub fn get_cookie_value_from_headers(
    headers: &http::HeaderMap,
    name: &str,
) -> Option<String> {
    let jar = CookieJar::from_headers(headers);
    jar.get(name).map(|c| c.value().to_string())
}

fn create_token_cookie(
    name: &'static str,
    value: Option<&str>,
    path: &'static str,
    max_age: Duration,
) -> Cookie<'static> {
    let (cookie_val, cookie_max_age) = match value {
        Some(val) if !val.is_empty() => (val.to_string(), max_age),
        _ => (String::new(), Duration::ZERO),
    };

    Cookie::build((name, cookie_val))
        .path(path)
        .max_age(cookie_max_age)
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict)
        .build()
}

fn extract_bearer_token(headers: &http::HeaderMap) -> Result<&str, Error> {
    headers
        .get(http::header::AUTHORIZATION)
        .ok_or(Error::InvalidToken)?
        .to_str()
        .map_err(|_| Error::InvalidToken)?
        .strip_prefix("Bearer ")
        .ok_or(Error::InvalidToken)
}
