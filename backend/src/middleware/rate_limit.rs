use axum::{
    extract::{ConnectInfo, Request},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;

/// Rate limiting entry for tracking requests
#[derive(Debug, Clone)]
struct RateLimitEntry {
    count: u32,
    window_start: Instant,
}

/// In-memory rate limiter (in production, use Redis)
pub type RateLimiter = Arc<RwLock<HashMap<String, RateLimitEntry>>>;

pub fn create_rate_limiter() -> RateLimiter {
    Arc::new(RwLock::new(HashMap::new()))
}

/// Rate limiting middleware for OAuth endpoints
pub async fn oauth_rate_limit_middleware(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Only apply rate limiting to OAuth endpoints
    if !req.uri().path().contains("/auth/oauth/") {
        return Ok(next.run(req).await);
    }

    let client_ip = addr.ip().to_string();

    // Rate limit: 10 requests per minute per IP for OAuth endpoints
    const MAX_REQUESTS: u32 = 10;
    const WINDOW_DURATION: Duration = Duration::from_secs(60);

    // This would be better stored in the app state, but for now using a simple approach
    // In production, use a proper rate limiting service like Redis
    static RATE_LIMITER: std::sync::OnceLock<RateLimiter> = std::sync::OnceLock::new();
    let rate_limiter = RATE_LIMITER.get_or_init(create_rate_limiter);

    let now = Instant::now();
    let mut limiter = rate_limiter.write().await;

    // Clean up expired entries
    limiter.retain(|_, entry| now.duration_since(entry.window_start) <= WINDOW_DURATION);

    // Check current rate limit
    let entry = limiter.entry(client_ip.clone()).or_insert_with(|| RateLimitEntry {
        count: 0,
        window_start: now,
    });

    // Reset window if expired
    if now.duration_since(entry.window_start) > WINDOW_DURATION {
        entry.count = 0;
        entry.window_start = now;
    }

    entry.count += 1;

    if entry.count > MAX_REQUESTS {
        tracing::warn!("OAuth rate limit exceeded for IP: {}", client_ip);
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    drop(limiter); // Release the lock
    Ok(next.run(req).await)
}
