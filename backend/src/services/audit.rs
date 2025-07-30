use serde::Serialize;
use std::fmt;

/// OAuth audit events for security monitoring
#[derive(Debug, Clone, Serialize)]
pub enum OAuthAuditEvent {
    /// OAuth flow initiated
    FlowInitiated {
        provider: String,
        client_ip: String,
        user_agent: Option<String>,
        redirect_url: Option<String>,
    },
    /// OAuth callback received
    CallbackReceived {
        provider: String,
        client_ip: String,
        state: String,
        success: bool,
        error: Option<String>,
    },
    /// User authenticated via OAuth
    UserAuthenticated {
        provider: String,
        user_id: i64,
        email: String,
        is_new_user: bool,
        client_ip: String,
    },
    /// OAuth security violation detected
    SecurityViolation {
        violation_type: String,
        client_ip: String,
        details: String,
    },
    /// Rate limit exceeded
    RateLimitExceeded {
        client_ip: String,
        endpoint: String,
    },
}

impl fmt::Display for OAuthAuditEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FlowInitiated { provider, client_ip, redirect_url, .. } => {
                write!(f, "OAuth flow initiated for {} from {} (redirect: {:?})", provider, client_ip, redirect_url)
            }
            Self::CallbackReceived { provider, client_ip, success, error, .. } => {
                if *success {
                    write!(f, "OAuth callback successful for {} from {}", provider, client_ip)
                } else {
                    write!(f, "OAuth callback failed for {} from {}: {:?}", provider, client_ip, error)
                }
            }
            Self::UserAuthenticated { provider, email, is_new_user, client_ip, .. } => {
                let user_type = if *is_new_user { "new" } else { "existing" };
                write!(f, "OAuth authentication successful for {} user {} via {} from {}", user_type, email, provider, client_ip)
            }
            Self::SecurityViolation { violation_type, client_ip, details } => {
                write!(f, "OAuth security violation: {} from {} - {}", violation_type, client_ip, details)
            }
            Self::RateLimitExceeded { client_ip, endpoint } => {
                write!(f, "OAuth rate limit exceeded from {} on {}", client_ip, endpoint)
            }
        }
    }
}

/// Log OAuth audit event with structured data
pub fn log_oauth_event(event: &OAuthAuditEvent) {
    match event {
        OAuthAuditEvent::SecurityViolation { .. } | OAuthAuditEvent::RateLimitExceeded { .. } => {
            tracing::warn!(
                event_type = "oauth_audit",
                event = ?event,
                message = %event,
                "OAuth security event"
            );
        }
        OAuthAuditEvent::CallbackReceived { success: false, .. } => {
            tracing::warn!(
                event_type = "oauth_audit",
                event = ?event,
                message = %event,
                "OAuth callback failed"
            );
        }
        _ => {
            tracing::info!(
                event_type = "oauth_audit",
                event = ?event,
                message = %event,
                "OAuth event"
            );
        }
    }
}

/// Extract client IP from request headers (considering proxies)
pub fn extract_client_ip(headers: &axum::http::HeaderMap) -> String {
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

/// Extract user agent from request headers
pub fn extract_user_agent(headers: &axum::http::HeaderMap) -> Option<String> {
    headers.get("user-agent")
        .and_then(|ua| ua.to_str().ok())
        .map(|s| s.to_string())
}
