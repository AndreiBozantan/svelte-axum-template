use sha2::{Digest, Sha256};

use crate::routes::auth::AuthError;

pub fn log_oauth_flow_initiated(provider: &str, headers: &axum::http::HeaderMap, redirect_url: &Option<&String>) {
    tracing::info!(
        event_type = "oauth_audit",
        provider = provider,
        client_ip = extract_client_ip(headers),
        user_agent = ?extract_user_agent(headers),
        redirect_url = ?redirect_url,
        message = "OAuth flow initiated"
    );
}

pub fn log_oauth_redirecting(provider: &str, headers: &axum::http::HeaderMap, auth_url: &url::Url, state: &str) {
    tracing::info!(
        event_type = "oauth_audit",
        provider = provider,
        client_ip = extract_client_ip(headers),
        user_agent = ?extract_user_agent(headers),
        auth_url = ?auth_url,
        state_hash = %hash_state(state),
        message = "OAuth flow initiated"
    );
}

pub fn log_oauth_callback_received(provider: &str, headers: &axum::http::HeaderMap, state: &str) {
    tracing::info!(
        event_type = "oauth_audit",
        provider = provider,
        client_ip = extract_client_ip(headers),
        state_hash = %hash_state(state),
        message = "OAuth callback received"
    );
}

pub fn log_oauth_security_violation(violation_type: &str, headers: &axum::http::HeaderMap, email: &str, state: &str) {
    tracing::warn!(
        event_type = "oauth_audit",
        violation_type = violation_type,
        client_ip = extract_client_ip(headers),
        email = email,
        state_hash = %hash_state(state),
        message = "OAuth security violation detected"
    );
}

pub fn log_oauth_create_new_user(provider: &str, headers: &axum::http::HeaderMap, email: &str, state: &str) {
    tracing::info!(
        event_type = "oauth_audit",
        provider = provider,
        email = email,
        client_ip = extract_client_ip(headers),
        state_hash = %hash_state(state),
        message = "Creating new user for OAuth login"
    );
}

pub fn log_oauth_user_authenticated(provider: &str, headers: &axum::http::HeaderMap, email: &str, state: &str) {
    tracing::info!(
        event_type = "oauth_audit",
        provider = provider,
        email = email,
        client_ip = extract_client_ip(headers),
        state_hash = %hash_state(state),
        message = "User authenticated via OAuth"
    );
}

pub fn log_oauth_rate_limit_exceeded(headers: &axum::http::HeaderMap, endpoint: &str) {
    tracing::warn!(
        event_type = "oauth_audit",
        client_ip = extract_client_ip(headers),
        endpoint = endpoint,
        message = "OAuth rate limit exceeded"
    );
}

pub fn log_user_login(headers: &axum::http::HeaderMap, username: &str) {
    tracing::info!(
        event_type = "auth_audit",
        client_ip = extract_client_ip(headers),
        user_agent = ?extract_user_agent(headers),
        username = username,
        message = "User login"
    );
}

pub fn log_invalid_password(headers: &axum::http::HeaderMap, username: &str) {
    tracing::warn!(
        event_type = "auth_audit",
        client_ip = extract_client_ip(headers),
        user_agent = ?extract_user_agent(headers),
        username = username,
        message = "Invalid password attempt"
    );
}

pub fn log_user_logout(headers: &axum::http::HeaderMap, user_id: &str, username: &str) {
    tracing::info!(
        event_type = "auth_audit",
        client_ip = extract_client_ip(headers),
        user_agent = ?extract_user_agent(headers),
        user_id = user_id,
        username = username,
        message = "User logout"
    );
}

pub fn log_token_refresh(headers: &axum::http::HeaderMap, user_id: i64, jti: &str, subject: &str) {
    tracing::info!(
        event_type = "auth_audit",
        client_ip = extract_client_ip(headers),
        user_agent = extract_user_agent(headers),
user_id = user_id,
        subject = subject,
        jti = jti,
        message = "Token refreshed"
    );
}

pub fn log_token_revoke(headers: &axum::http::HeaderMap, jti: &str, subject: &str) {
    tracing::info!(
        event_type = "auth_audit",
        client_ip = extract_client_ip(headers),
        user_agent = extract_user_agent(headers),
subject = subject,
        jti = jti,
        message = "Token revoked"
    );
}

pub fn log_auth_error(error: &AuthError) {
    tracing::error!(
        event_type = "auth_audit",
        error_type = "AuthError",
        error_subtype = %std::any::type_name_of_val(error),
        error_message = %error,
        message = "Authentication error occurred"
    );
}

fn extract_client_ip(headers: &axum::http::HeaderMap) -> String {
    // Check common proxy headers first
    if let Some(forwarded_for) = headers.get("x-forwarded-for") {
        if let Ok(value) = forwarded_for.to_str() {
            if let Some(ip) = value.split(',').next() {
                return ip.trim().to_string();
            }
        }
    }

    if let Some(real_ip) = headers.get("x-real-ip") {
        if let Ok(value) = real_ip.to_str() {
            return value.to_string();
        }
    }

    // Fallback to connection info (set by router)
    "unknown".to_string()
}

fn extract_user_agent(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get("user-agent")
        .and_then(|ua| ua.to_str().ok())
        .map(|s| s.to_string())
}

// Helper to avoid logging raw state token
fn hash_state(state: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(state.as_bytes());
    format!("{:x}", hasher.finalize())
}
