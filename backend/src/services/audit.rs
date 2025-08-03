pub fn log_oauth_flow_initiated(
    provider: &str,
    headers: &axum::http::HeaderMap,
    redirect_url: &Option<&String>,
) {
    let client_ip = extract_client_ip(headers);
    let user_agent = extract_user_agent(headers);
    tracing::info!(
        event_type = "oauth_audit",
        provider = provider,
        client_ip = client_ip,
        user_agent = ?user_agent,
        redirect_url = ?redirect_url,
        message = "OAuth flow initiated"
    );
}

pub fn log_oauth_callback_received(
    provider: &str,
    headers: &axum::http::HeaderMap,
    state: &str,
    err: &Option<impl std::error::Error>,
) {
    let client_ip = extract_client_ip(headers);
    tracing::info!(
        event_type = "oauth_audit",
        provider = provider,
        client_ip = client_ip,
        state = state,
        success = err.is_none(),
        error = ?err,
        message = "OAuth callback received"
    );
}

pub fn log_oauth_security_violation(
    violation_type: &str,
    headers: &axum::http::HeaderMap,
    details: &str,
) {
    let client_ip = extract_client_ip(headers);
    tracing::warn!(
        event_type = "oauth_audit",
        violation_type = violation_type,
        client_ip = client_ip,
        details = details,
        message = "OAuth security violation detected"
    );
}

pub fn log_oauth_user_authenticated(
    provider: &str,
    headers: &axum::http::HeaderMap,
    user_id: i64,
    email: &str,
    is_new_user: bool,
) {
    let client_ip = extract_client_ip(headers);
    tracing::info!(
        event_type = "oauth_audit",
        provider = provider,
        user_id = user_id,
        email = email,
        is_new_user = is_new_user,
        client_ip = client_ip,
        message = "User authenticated via OAuth"
    );
}

pub fn log_oauth_rate_limit_exceeded(
    headers: &axum::http::HeaderMap,
    endpoint: &str,
) {
    let client_ip = extract_client_ip(headers);
    tracing::warn!(
        event_type = "oauth_audit",
        client_ip = client_ip,
        endpoint = endpoint,
        message = "OAuth rate limit exceeded"
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
    headers.get("user-agent")
        .and_then(|ua| ua.to_str().ok())
        .map(|s| s.to_string())
}
