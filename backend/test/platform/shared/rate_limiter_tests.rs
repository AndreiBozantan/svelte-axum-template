use crate::platform::rate_limiter::extract_client_ip;
use axum::http::Request;

#[test]
fn test_extract_client_ip() -> Result<(), axum::http::Error> {
    // Test X-Forwarded-For header
    let req1 = Request::builder()
        .header("x-forwarded-for", "203.0.113.195, 70.41.3.18, 150.172.238.178")
        .body(())?;
    assert_eq!(extract_client_ip(&req1), "203.0.113.195");

    // Test X-Real-IP header
    let req2 = Request::builder().header("x-real-ip", "203.0.113.196").body(())?;
    assert_eq!(extract_client_ip(&req2), "203.0.113.196");

    // Test fallback
    let req3 = Request::builder().body(())?;
    assert_eq!(extract_client_ip(&req3), "unknown");
    Ok(())
}
