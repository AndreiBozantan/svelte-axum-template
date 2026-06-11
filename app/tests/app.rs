use axum::http::StatusCode;
use axum::http::header;
use axum_test::TestServer;

#[tokio::test]
async fn test_static_file_caching() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = platform::common::Context::create_test_context().await?;

    let router = app::create_router(ctx);
    let server = TestServer::new(router);

    // Request index.html first time (should be 200 OK)
    let response = server.get("/").await;
    response.assert_status(StatusCode::OK);

    let etag = response
        .headers()
        .get(header::ETAG)
        .ok_or("ETag header is missing")?
        .to_str()?
        .to_string();

    assert!(!etag.is_empty(), "ETag should not be empty");

    // Request index.html second time with If-None-Match (should be 304 Not Modified)
    let response_cached = server.get("/").add_header(header::IF_NONE_MATCH, &etag).await;

    response_cached.assert_status(StatusCode::NOT_MODIFIED);
    assert!(response_cached.text().is_empty(), "304 response body should be empty");
    Ok(())
}
