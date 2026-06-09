use axum::http::StatusCode;
use axum::http::header;
use serde_json::Value;

use super::super::*;

#[tokio::test]
async fn protected_route_without_token() -> anyhow::Result<()> {
    let server = create_test_server().await?;
    let response = server.get("/api/users/me").await;
    response.assert_status(StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn protected_route_with_invalid_token() -> anyhow::Result<()> {
    let server = create_test_server().await?;
    let response = server
        .get("/api/users/me")
        .add_header(header::AUTHORIZATION, "Bearer invalid_token")
        .await;
    response.assert_status(StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn protected_route_with_valid_token() -> anyhow::Result<()> {
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
async fn user_info_unauthenticated_returns_401() -> anyhow::Result<()> {
    let server = create_test_server().await?;
    let response = server.get("/api/users/me").await;
    response.assert_status(StatusCode::UNAUTHORIZED);
    let body: Value = response.json();
    assert_eq!(body["code"], "invalid_token");
    Ok(())
}
