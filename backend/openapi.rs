use utoipa::OpenApi;

struct SecurityAddon;

impl utoipa::Modify for SecurityAddon {
    fn modify(
        &self,
        openapi: &mut utoipa::openapi::OpenApi,
    ) {
        if let Some(components) = openapi.components.as_mut() {
            use utoipa::openapi::security::{ApiKey, ApiKeyValue, SecurityScheme};
            components.add_security_scheme(
                "cookieAuth",
                SecurityScheme::ApiKey(ApiKey::Cookie(ApiKeyValue::new("access_token"))),
            );
        }
    }
}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "svelaxum API",
        version = env!("CARGO_PKG_VERSION"),
        description = "See docs/api/conventions.md for response shapes.",
    ),
    paths(),
    components(),
    modifiers(&SecurityAddon)
)]
pub struct ApiDoc;

pub async fn export() -> Result<(), String> {
    if std::env::args().nth(1).as_deref() != Some("export-openapi") {
        return Ok(());
    }

    let dummy_ctx = crate::platform::common::Context::create_test_context()
        .await
        .map_err(|err| err.to_string())?;

    let openapi = crate::router::create(dummy_ctx).to_openapi();
    let spec = openapi.to_pretty_json().map_err(|err| err.to_string())?;
    println!("{spec}");
    std::process::exit(0);
}
