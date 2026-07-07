use axum::http::Request;
use axum::http::StatusCode;
use axum::routing::get;
use axum_test::TestServer;
use governor::middleware::NoOpMiddleware;
use std::sync::Arc;
use std::sync::OnceLock;
use tower_governor::governor::GovernorConfig;

use crate::platform::config::RateLimitSettings;
use crate::platform::rate_limiter::ClientIpExtractor;
use crate::platform::rate_limiter::add_rate_limiting;
use crate::platform::rate_limiter::extract_client_ip;

#[test]
fn test_extract_client_ip() -> Result<(), axum::http::Error> {
    use std::sync::atomic::Ordering;

    // by default, trusted_proxy is false
    crate::platform::rate_limiter::TRUSTED_PROXY.store(false, Ordering::Relaxed);

    // test headers ignored when trusted_proxy is false
    let req1 = Request::builder()
        .header("x-forwarded-for", "203.0.113.195, 70.41.3.18, 150.172.238.178")
        .body(())?;
    assert_eq!(extract_client_ip(&req1), "unknown");

    let req2 = Request::builder().header("x-real-ip", "203.0.113.196").body(())?;
    assert_eq!(extract_client_ip(&req2), "unknown");

    // enable trusted proxy
    crate::platform::rate_limiter::TRUSTED_PROXY.store(true, Ordering::Relaxed);

    // test headers honored when trusted_proxy is true
    let req3 = Request::builder()
        .header("x-forwarded-for", "203.0.113.195, 70.41.3.18, 150.172.238.178")
        .body(())?;
    assert_eq!(extract_client_ip(&req3), "203.0.113.195");

    let req4 = Request::builder().header("x-real-ip", "203.0.113.196").body(())?;
    assert_eq!(extract_client_ip(&req4), "203.0.113.196");

    // test fallback
    let req5 = Request::builder().body(())?;
    assert_eq!(extract_client_ip(&req5), "unknown");
    Ok(())
}

#[tokio::test]
async fn test_rate_limiting_middleware_enabled() {
    static TEST_LIMITER_CONFIG: OnceLock<Arc<GovernorConfig<ClientIpExtractor, NoOpMiddleware>>> = OnceLock::new();

    let settings = RateLimitSettings {
        enabled: true,
        rate: 1,
        period_in_seconds: 10,
        burst_size: 1,
    };

    let router = utoipax::router::OpenApiRouter::new().route("/test", get(|| async { "ok" }));
    let router = add_rate_limiting(router, &settings, &TEST_LIMITER_CONFIG);
    let router = router.split_for_parts().0;
    let service = router.into_make_service_with_connect_info::<std::net::SocketAddr>();
    let server = TestServer::new(service);

    // first request should succeed
    let response1 = server.get("/test").await;
    response1.assert_status(StatusCode::OK);
    assert_eq!(response1.text(), "ok");

    // second request should be rate limited (429)
    let response2 = server.get("/test").await;
    response2.assert_status(StatusCode::TOO_MANY_REQUESTS);

    let body: serde_json::Value = response2.json();
    assert_eq!(body["code"], "too_many_requests");
    assert_eq!(body["message"], "Too many requests. Please try again later.");
}

#[tokio::test]
async fn test_rate_limiting_middleware_disabled() {
    static TEST_LIMITER_CONFIG_DISABLED: OnceLock<Arc<GovernorConfig<ClientIpExtractor, NoOpMiddleware>>> =
        OnceLock::new();

    let settings = RateLimitSettings {
        enabled: false,
        rate: 1,
        period_in_seconds: 10,
        burst_size: 1,
    };

    let router = utoipax::router::OpenApiRouter::new().route("/test", get(|| async { "ok" }));
    let router = add_rate_limiting(router, &settings, &TEST_LIMITER_CONFIG_DISABLED);
    let router = router.split_for_parts().0;
    let service = router.into_make_service_with_connect_info::<std::net::SocketAddr>();
    let server = TestServer::new(service);

    // all 20 parallel requests should succeed because rate limiting is disabled
    let server = Arc::new(server);
    let mut handles = Vec::new();

    for _ in 0..20 {
        let server = Arc::clone(&server);
        handles.push(tokio::spawn(async move {
            let response = server.get("/test").await;
            response.assert_status(StatusCode::OK);
        }));
    }

    for handle in handles {
        assert!(handle.await.is_ok());
    }
}
