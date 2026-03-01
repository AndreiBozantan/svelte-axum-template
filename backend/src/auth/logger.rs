use sha2::{Digest, Sha256};

pub fn log_auth_error(error: &dyn std::error::Error) {
    tracing::error!(
        event_type = "auth_audit",
        error_type = "AuthError",
        error_subtype = std::any::type_name_of_val(error),
        error_message = %error,
        message = "Authentication error occurred"
    );
}

pub fn log_oauth_flow_initiated(provider: &str, headers: &axum::http::HeaderMap, redirect_url: &Option<&String>) {
    tracing::info!(
        event_type = "oauth_audit",
        client_ip = extract_client_ip(headers),
        user_agent = extract_user_agent(headers),
        message = "OAuth flow initiated",
        provider,
        redirect_url,
    );
}

pub fn log_oauth_redirecting(provider: &str, headers: &axum::http::HeaderMap, auth_url: &url::Url, state: &str) {
    tracing::info!(
        event_type = "oauth_audit",
        client_ip = extract_client_ip(headers),
        user_agent = extract_user_agent(headers),
        state_hash = hash_state(state),
        message = "OAuth flow redirecting",
        provider,
        %auth_url,
    );
}

pub fn log_oauth_callback_received(provider: &str, headers: &axum::http::HeaderMap, state: &str, email: &str) {
    tracing::info!(
        event_type = "oauth_audit",
        client_ip = extract_client_ip(headers),
        user_agent = extract_user_agent(headers),
        state_hash = hash_state(state),
        message = "OAuth callback received",
        provider,
        email,
    );
}

pub fn log_oauth_security_violation(violation_type: &str, headers: &axum::http::HeaderMap, email: &str, state: &str) {
    tracing::warn!(
        event_type = "oauth_audit",
        client_ip = extract_client_ip(headers),
        user_agent = extract_user_agent(headers),
        state_hash = hash_state(state),
        message = "OAuth security violation detected",
        violation_type,
        email,
    );
}

pub fn log_oauth_create_new_user(provider: &str, headers: &axum::http::HeaderMap, email: &str, state: &str) {
    tracing::info!(
        event_type = "oauth_audit",
        client_ip = extract_client_ip(headers),
        user_agent = extract_user_agent(headers),
        state_hash = hash_state(state),
        message = "Creating new user for OAuth login",
        provider,
        email,
    );
}

pub fn log_oauth_user_authenticated(provider: &str, headers: &axum::http::HeaderMap, email: &str, state: &str) {
    tracing::info!(
        event_type = "oauth_audit",
        client_ip = extract_client_ip(headers),
        user_agent = extract_user_agent(headers),
        state_hash = hash_state(state),
        message = "User authenticated via OAuth",
        provider,
        email,
    );
}

pub fn log_oauth_rate_limit_exceeded(headers: &axum::http::HeaderMap, endpoint: &str) {
    tracing::warn!(
        event_type = "oauth_audit",
        client_ip = extract_client_ip(headers),
        user_agent = extract_user_agent(headers),
        message = "OAuth rate limit exceeded",
        endpoint,
    );
}

pub fn log_user_login(headers: &axum::http::HeaderMap, username: &str) {
    tracing::info!(
        event_type = "auth_audit",
        client_ip = extract_client_ip(headers),
        user_agent = extract_user_agent(headers),
        message = "User login attempt",
        username,
    );
}

pub fn log_user_login_success(headers: &axum::http::HeaderMap, username: &str) {
    tracing::info!(
        event_type = "auth_audit",
        client_ip = extract_client_ip(headers),
        user_agent = extract_user_agent(headers),
        message = "User login successful",
        username,
    );
}

pub fn log_missing_password(headers: &axum::http::HeaderMap, username: &str) {
    tracing::warn!(
        event_type = "auth_audit",
        client_ip = extract_client_ip(headers),
        user_agent = extract_user_agent(headers),
        message = "Attempt login without password",
        username,
    );
}

pub fn log_invalid_password(headers: &axum::http::HeaderMap, username: &str) {
    tracing::warn!(
        event_type = "auth_audit",
        client_ip = extract_client_ip(headers),
        user_agent = extract_user_agent(headers),
        message = "Invalid password attempt",
        username,
    );
}

pub fn log_user_logout(headers: &axum::http::HeaderMap, user_id: &str, username: &str) {
    tracing::info!(
        event_type = "auth_audit",
        client_ip = extract_client_ip(headers),
        user_agent = extract_user_agent(headers),
        message = "User logout",
        user_id,
        username,
    );
}

pub fn log_token_refresh(headers: &axum::http::HeaderMap, user_id: i64, jti: &str, subject: &str) {
    tracing::info!(
        event_type = "auth_audit",
        client_ip = extract_client_ip(headers),
        user_agent = extract_user_agent(headers),
        message = "Token refreshed",
        user_id,
        subject,
        jti,
    );
}

pub fn log_token_revoke(headers: &axum::http::HeaderMap, jti: &str, subject: &str) {
    tracing::info!(
        event_type = "auth_audit",
        client_ip = extract_client_ip(headers),
        user_agent = extract_user_agent(headers),
        message = "Token revoked",
        subject,
        jti,
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
