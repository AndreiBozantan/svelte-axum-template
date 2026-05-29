use axum::extract::{ConnectInfo, Request};
use std::net::SocketAddr;

/// Clean up and canonicalize email addresses for consistent storage and comparison.
#[must_use]
pub fn normalize_email(email: &str) -> String {
    email.trim().to_ascii_lowercase()
}

/// Returns the canonical client IP for rate limiting, logging, and audit trails.
///
/// Strategy: always trust the real TCP peer from `ConnectInfo`. If your deployment
/// sits behind a trusted reverse proxy, swap this for a whitelist-gated
/// `X-Forwarded-For` parser — but never read XFF unconditionally, because
/// clients can forge it.
pub fn canonical_client_ip(req: &Request) -> String {
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map_or_else(|| "unknown".to_string(), |ConnectInfo(addr)| addr.ip().to_string())
}
