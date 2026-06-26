use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    info(
        title = "svelaxum API",
        version = env!("CARGO_PKG_VERSION"),
        description = "See docs/api/conventions.md for response shapes.",
    ),
    paths(),
    components()
)]
pub struct ApiDoc;
