use axum::http::Request;
use axum::response::IntoResponse;
use axum::response::Response;
use governor::middleware::NoOpMiddleware;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::OnceLock;
use tower_governor::errors::GovernorError;
use tower_governor::governor::GovernorConfig;
use tower_governor::governor::GovernorConfigBuilder;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientIpExtractor;

impl tower_governor::key_extractor::KeyExtractor for ClientIpExtractor {
    type Key = String;

    fn extract<B>(
        &self,
        req: &Request<B>,
    ) -> Result<Self::Key, GovernorError> {
        Ok(extract_client_ip(req))
    }
}

pub static GLOBAL_LIMITER_CONFIG: OnceLock<Arc<GovernorConfig<ClientIpExtractor, NoOpMiddleware>>> = OnceLock::new();
pub static LOGIN_LIMITER_CONFIG: OnceLock<Arc<GovernorConfig<ClientIpExtractor, NoOpMiddleware>>> = OnceLock::new();

pub fn add_global_rate_limiting<S>(
    router: axum::Router<S>,
    settings: &crate::platform::config::RateLimitSettings,
) -> axum::Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    add_rate_limiting(router, settings, &GLOBAL_LIMITER_CONFIG)
}

pub fn add_login_rate_limiting<S>(
    router: axum::Router<S>,
    settings: &crate::platform::config::RateLimitSettings,
) -> axum::Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    add_rate_limiting(router, settings, &LOGIN_LIMITER_CONFIG)
}

pub fn add_rate_limiting<S>(
    router: axum::Router<S>,
    settings: &crate::platform::config::RateLimitSettings,
    limiter_config: &'static OnceLock<Arc<GovernorConfig<ClientIpExtractor, NoOpMiddleware>>>,
) -> axum::Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    if !settings.enabled || settings.rate == 0 || settings.period_in_seconds == 0 || settings.burst_size == 0 {
        return router;
    }

    let config = limiter_config.get_or_init(|| {
        let period = std::time::Duration::from_secs(settings.period_in_seconds);
        let replenishment_interval = period / settings.rate;
        let c = GovernorConfigBuilder::default()
            .period(replenishment_interval)
            .burst_size(settings.burst_size)
            .key_extractor(ClientIpExtractor)
            .finish()
            .unwrap_or_else(|| unreachable!("GovernorConfigBuilder should always succeed with valid values"));
        Arc::new(c)
    });

    let layer = tower_governor::GovernorLayer::new(config.clone()).error_handler(custom_error_handler);
    router.layer(layer)
}

pub fn custom_error_handler(_err: GovernorError) -> Response {
    crate::platform::api::Error::too_many_requests().into_response()
}

#[must_use]
pub fn extract_client_ip<B>(req: &Request<B>) -> String {
    // check common proxy headers
    if let Some(forwarded_for) = req.headers().get("x-forwarded-for")
        && let Ok(value) = forwarded_for.to_str()
        && let Some(ip) = value.split(',').next()
    {
        return ip.trim().to_string();
    }

    if let Some(real_ip) = req.headers().get("x-real-ip")
        && let Ok(value) = real_ip.to_str()
    {
        return value.to_string();
    }

    // fallback to Axum's SocketAddr ConnectInfo
    if let Some(axum::extract::ConnectInfo(addr)) = req.extensions().get::<axum::extract::ConnectInfo<SocketAddr>>() {
        return addr.ip().to_string();
    }

    "unknown".to_string()
}
