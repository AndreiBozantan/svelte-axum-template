use std::net::SocketAddr;

use tracing::error;
use tracing::info;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::cli;
use crate::router;

use crate::platform::common;
use crate::platform::config;
use crate::platform::jwt;
use crate::platform::migrations;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Configuration error: {0}")]
    ConfigLoadingFailed(#[from] config::Error),

    #[error("Database error: {0}")]
    DatabaseOperationFailed(#[from] sqlx::Error),

    #[error("JWT error: {0}")]
    JwtOperationFailed(#[from] jwt::Error),

    #[error("Migration error: {0}")]
    MigrationFailed(#[from] migrations::Error),

    #[error("CLI error: {0}")]
    CliOperationFailed(#[from] cli::Error),

    #[error("Network address parsing error: {0}")]
    AddressParsingFailed(#[from] std::net::AddrParseError),

    #[error("Server error: {0}")]
    ServerStartingFailed(#[from] std::io::Error),

    #[error("Server error: {0}")]
    HttpClientCreationFailed(#[from] reqwest::Error),

    #[error("Context creation error: {0}")]
    ContextCreationFailed(#[from] common::ContextCreationError),
}

pub async fn run() {
    #[cfg(debug_assertions)]
    {
        dotenvy::dotenv().ok();
    }
    if let Err(error) = start_server().await {
        use std::error::Error as StdError;
        eprintln!("❌ {error}\n");
        let mut source = error.source();
        while let Some(err) = source {
            eprintln!("Caused by: {err}");
            source = err.source();
        }
        let backtrace = std::backtrace::Backtrace::capture();
        eprintln!("{backtrace}");
        std::process::exit(1);
    }
}

async fn start_server() -> Result<(), Error> {
    let settings = config::AppSettings::new()?;
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(&settings.server.log_directives))
        .with(tracing_subscriber::fmt::layer().with_file(true).with_line_number(true))
        .init();

    info!("starting server... 🚀 ");
    info!("logging: {}", settings.server.log_directives);
    info!("app_env: {}", settings.server.env);
    info!("sql_url: {}", settings.database.url);
    info!("cfg_dir: {}", settings.get_config_dir_str()?);
    info!("address: http://{}", settings.get_server_address());
    info!("configs: {:#?}", &settings);

    let jwt_secret = jwt::get_jwt_secret()?;
    let ctx = common::Context::create(settings, &jwt_secret).await?;

    if !cli::run_cli(&ctx).await? {
        migrations::run_migrations(&ctx).await?;

        let addr = ctx.settings.get_server_address().parse::<SocketAddr>()?;
        let router = router::create(ctx.clone()).into_make_service_with_connect_info::<SocketAddr>();
        let listener = tokio::net::TcpListener::bind(addr).await?;

        crate::platform::identity::oauth::check_oauth_config(&ctx.settings.oauth);
        axum::serve(listener, router)
            .with_graceful_shutdown(shutdown_signal())
            .await?;
    }

    Ok(())
}

async fn shutdown_signal() {
    match tokio::signal::ctrl_c().await {
        Ok(()) => info!("graceful shutdown initiated"),
        Err(error) => error!(%error, "error during shutdown"),
    }
}
