use sha2::{Digest, Sha256};

pub fn log_internal_error(error: &dyn std::error::Error, context: &str) {
    tracing::error!(
        event_type = "auth",
        error_type = std::any::type_name_of_val(error),
        error_message = %error,
        context,
        message = "Internal error occurred"
    );
}

pub fn log_auth_error(error: &dyn std::error::Error) {
    tracing::error!(
        event_type = "auth",
        error_type = std::any::type_name_of_val(error),
        error_message = %error,
        message = "Authentication error occurred"
    );
}

pub fn log_invalid_config(field_name: &str, value: &str) {
    tracing::warn!(
        event_type = "auth",
        field_name,
        value,
        message = "Invalid auth config value",
    );
}

pub fn log_provider_api_error(status: axum::http::StatusCode, provider: &str) {
    tracing::error!(
        event_type = "auth",
        error_type = "provider_api",
        provider,
        status = %status,
        message = "OAuth provider API returned error status"
    );
}

pub fn log_invalid_user_info(field_name: &str, value: &str, provider: &str) {
    tracing::warn!(
        event_type = "auth",
        field_name,
        value,
        provider,
        message = "Invalid user info",
    );
}

pub fn log_redirect_violation(violation: &str, url: &str) {
    tracing::warn!(
        event_type = "auth",
        violation,
        url,
        message = "Redirect URL validation failed"
    );
}

pub fn log_oauth_flow_initiated(headers: &axum::http::HeaderMap, redirect_url: &Option<&String>, provider: &str) {
    tracing::info!(
        event_type = "auth",
        client_ip = extract_client_ip(headers),
        user_agent = extract_user_agent(headers),
        message = "OAuth flow initiated",
        provider,
        redirect_url,
    );
}

pub fn log_oauth_redirecting(headers: &axum::http::HeaderMap, auth_url: &url::Url, provider: &str) {
    tracing::info!(
        event_type = "auth",
        client_ip = extract_client_ip(headers),
        user_agent = extract_user_agent(headers),
        message = "OAuth flow redirecting",
        provider,
        %auth_url,
    );
}

pub fn log_oauth_callback_received(headers: &axum::http::HeaderMap, state: &str, email: &str, provider: &str) {
    tracing::info!(
        event_type = "auth",
        client_ip = extract_client_ip(headers),
        user_agent = extract_user_agent(headers),
        state_hash = hash_state(state),
        message = "OAuth callback received",
        provider,
        email,
    );
}

pub fn log_oauth_security_violation(
    headers: &axum::http::HeaderMap,
    state: &str,
    email: &str,
    violation_type: &str,
    provider: &str,
) {
    tracing::warn!(
        event_type = "auth",
        client_ip = extract_client_ip(headers),
        user_agent = extract_user_agent(headers),
        state_hash = hash_state(state),
        message = "OAuth security violation detected",
        violation_type,
        email,
        provider,
    );
}

pub fn log_oauth_user_authenticated(headers: &axum::http::HeaderMap, state: &str, email: &str, provider: &str) {
    tracing::info!(
        event_type = "auth",
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
        event_type = "auth",
        client_ip = extract_client_ip(headers),
        user_agent = extract_user_agent(headers),
        message = "OAuth rate limit exceeded",
        endpoint,
    );
}

pub fn log_user_login(headers: &axum::http::HeaderMap, email: &str) {
    tracing::info!(
        event_type = "auth",
        client_ip = extract_client_ip(headers),
        user_agent = extract_user_agent(headers),
        message = "User login attempt",
        email,
    );
}

pub fn log_user_login_success(headers: &axum::http::HeaderMap, email: &str) {
    tracing::info!(
        event_type = "auth",
        client_ip = extract_client_ip(headers),
        user_agent = extract_user_agent(headers),
        message = "User login successful",
        email,
    );
}

pub fn log_missing_password(headers: &axum::http::HeaderMap, email: &str) {
    tracing::warn!(
        event_type = "auth",
        client_ip = extract_client_ip(headers),
        user_agent = extract_user_agent(headers),
        message = "Attempt login without password",
        email,
    );
}

pub fn log_invalid_password(headers: &axum::http::HeaderMap, email: &str) {
    tracing::warn!(
        event_type = "auth",
        client_ip = extract_client_ip(headers),
        user_agent = extract_user_agent(headers),
        message = "Invalid password attempt",
        email,
    );
}

pub fn log_user_logout(headers: &axum::http::HeaderMap, user_id: &str, email: &str) {
    tracing::info!(
        event_type = "auth",
        client_ip = extract_client_ip(headers),
        user_agent = extract_user_agent(headers),
        message = "User logout",
        user_id,
        email,
    );
}

pub fn log_token_refresh(headers: &axum::http::HeaderMap, user_id: i64, jti: &str, subject: &str) {
    tracing::info!(
        event_type = "auth",
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
        event_type = "auth",
        client_ip = extract_client_ip(headers),
        user_agent = extract_user_agent(headers),
        message = "Token revoked",
        subject,
        jti,
    );
}

pub fn log_csrf_mismatch(headers: Option<&axum::http::HeaderMap>, expected: &str, got: &str) {
    tracing::warn!(
        event_type = "auth",
        client_ip = headers.map(extract_client_ip).unwrap_or_else(|| "unknown".to_string()),
        user_agent = headers.and_then(extract_user_agent),
        expected_hash = hash_state(expected),
        got_hash = hash_state(got),
        message = "CSRF token mismatch detected"
    );
}

pub fn log_cookie_error(headers: &axum::http::HeaderMap, reason: &str) {
    tracing::warn!(
        event_type = "auth",
        client_ip = extract_client_ip(headers),
        user_agent = extract_user_agent(headers),
        reason,
        message = "Authentication cookie error"
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
