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

pub fn run_export() -> Result<(), String> {
    if std::env::args().nth(1).as_deref() == Some("export-openapi") {
        let spec = ApiDoc::openapi().to_pretty_json().map_err(|err| err.to_string())?;
        println!("{spec}");
        std::process::exit(0);
    }
    Ok(())
}
