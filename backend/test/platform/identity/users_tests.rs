use axum::http::StatusCode;
use axum::http::header;
use serde_json::Value;

use crate::test::test_server::*;

#[tokio::test]
async fn protected_route_without_token() -> TestResult {
    let server = create_test_server().await?;
    let response = server.get("/api/users/me").await;
    response.assert_status(StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn protected_route_with_invalid_token() -> TestResult {
    let server = create_test_server().await?;
    let response = server
        .get("/api/users/me")
        .add_header(header::AUTHORIZATION, "Bearer invalid_token")
        .await;
    response.assert_status(StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn protected_route_with_valid_token() -> TestResult {
    let server = create_test_server().await?;
    let (_body, access_token, _refresh_token) = login_testuser_and_get_tokens(&server).await?;
    let api_response = server
        .get("/api/users/me")
        .add_cookie(cookie::Cookie::new("access_token", access_token.clone()))
        .await;
    api_response.assert_status(StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn user_info_unauthenticated_returns_401() -> TestResult {
    let server = create_test_server().await?;
    let response = server.get("/api/users/me").await;
    response.assert_status(StatusCode::UNAUTHORIZED);
    let body: Value = response.json();
    assert_eq!(body["code"], "invalid_token");
    Ok(())
}

#[tokio::test]
async fn list_users_invalid_query_params() -> TestResult {
    let server = create_test_server().await?;
    let (_body, access_token, _refresh_token) = login_testuser_and_get_tokens(&server).await?;
    let response = server
        .get("/api/users?limit=not_a_number")
        .add_cookie(cookie::Cookie::new("access_token", access_token))
        .await;
    response.assert_status(StatusCode::BAD_REQUEST);
    let r: Value = response.json();
    assert_eq!(r["code"], "validation_failed");
    assert!(
        r["details"]["query"][0]
            .as_str()
            .ok_or("expected details.query[0] to be a string")?
            .contains("Failed to deserialize query string")
    );
    Ok(())
}
