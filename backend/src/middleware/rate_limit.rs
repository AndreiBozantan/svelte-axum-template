use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Request};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;
use tokio::sync::RwLock;

/// Rate limiting entry for tracking requests
#[derive(Debug, Clone)]
pub struct RateLimitEntry {
    pub count: u32,
    pub window_start: Instant,
}

/// In-memory rate limiter (in production, use Redis)
pub type RateLimiter = Arc<RwLock<HashMap<String, RateLimitEntry>>>;

#[must_use] 
pub fn create_rate_limiter() -> RateLimiter {
    Arc::new(RwLock::new(HashMap::new()))
}

/// Rate limiting middleware for OAuth endpoints
pub async fn oauth_rate_limit_middleware(req: Request, next: Next) -> Result<Response, StatusCode> {
    // rate limit: 100 requests per minute per IP for auth endpoints
    // TODO: make this configurable
    const MAX_REQUESTS: u32 = 100;
    const WINDOW_DURATION: Duration = Duration::from_secs(60);

    // this would be better stored in the app state, but for now using a simple approach
    // in production, use a proper rate limiting service like Redis
    static RATE_LIMITER: std::sync::OnceLock<RateLimiter> = std::sync::OnceLock::new();

    // apply rate limiting to all auth endpoints
    if !req.uri().path().contains("/auth/") {
        return Ok(next.run(req).await);
    }

    let client_ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map_or_else(|| "unknown".to_string(), |ConnectInfo(a)| a.ip().to_string());

    let rate_limiter = RATE_LIMITER.get_or_init(create_rate_limiter);

    let now = Instant::now();
    let mut limiter = rate_limiter.write().await;

    // clean up expired entries
    limiter.retain(|_, entry| now.duration_since(entry.window_start) <= WINDOW_DURATION);

    // check current rate limit
    let entry = limiter.entry(client_ip.clone()).or_insert_with(|| RateLimitEntry {
        count: 0,
        window_start: now,
    });

    // reset window if expired
    if now.duration_since(entry.window_start) > WINDOW_DURATION {
        entry.count = 0;
        entry.window_start = now;
    }

    entry.count += 1;

    if entry.count > MAX_REQUESTS {
        tracing::warn!("auth rate limit exceeded for IP: {}", client_ip);
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    drop(limiter); // release the lock
    Ok(next.run(req).await)
}
