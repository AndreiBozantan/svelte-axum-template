use std::io;
use std::io::Write;

use clap::{Parser, Subcommand};

use crate::app;
use crate::auth;
use crate::common;
use crate::db;

// TODO: add support for secret rotation (should mark all tokens as invalid)
// TODO: add support for expired tokens cleanup

#[rustfmt::skip]
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error("Migration creation failed")]
    MigrationCreateFailed { source: app::MigrationError },

    // For the Status command, only actual errors from check_pending should be wrapped.
    // NoMigrationsApplied is handled as informational output.
    #[error("Checking migration status failed")]
    MigrationStatusCheckFailed { source: app::MigrationError },

    #[error("Running migrations failed")]
    MigrationRunFailed { source: app::MigrationError },

    #[error("Password hashing failed")]
    PasswordHashFailed { #[from] source: argon2::password_hash::Error },

    #[error("Failed to read password input")]
    PasswordReadFailed { #[from] source: std::io::Error },

    // The Other(String) variant is kept as a fallback, though ideally all errors should be specific.
    #[error("An unexpected CLI error occurred: {0}")]
    Other(String),
}

#[derive(Parser)]
#[command(name = "migrate")]
#[command(about = "Database migration utility", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    command: Option<CliCommand>,
}

#[derive(Subcommand)]
enum CliCommand {
    /// run database migrations
    Migrate {
        #[command(subcommand)]
        action: MigrateAction,
    },

    /// create an admin user
    CreateAdmin {
        /// email for the admin user
        #[arg(short, long)]
        email: String,
    },
}

#[derive(Subcommand)]
enum MigrateAction {
    /// create a new migration file
    Create { name: String },

    /// list all available migrations
    List,

    /// check if there are pending migrations
    Status,

    /// run all pending migrations
    Run,
}

#[allow(clippy::unit_arg)]
pub async fn run_cli(ctx: &common::ArcContext) -> Result<bool, CliError> {
    let cli = Cli::parse();
    match cli.command {
        None => {
            tracing::info!("CLI command not provided. Use --help for CLI usage.");
            Ok(false)
        }
        Some(CliCommand::Migrate { action }) => {
            exec_migrate_command(action, ctx).await?;
            Ok(true)
        }
        Some(CliCommand::CreateAdmin { email }) => {
            create_admin(email, ctx).await?;
            Ok(true)
        }
    }
}

async fn exec_migrate_command(action: MigrateAction, ctx: &common::ArcContext) -> Result<(), CliError> {
    match action {
        MigrateAction::Create { name } => migrate_action_create(&name),
        MigrateAction::List => migrate_action_list(),
        MigrateAction::Status => migrate_action_status(ctx).await,
        MigrateAction::Run => migrate_action_run(ctx).await,
    }
}

fn migrate_action_create(name: &str) -> Result<(), CliError> {
    let file_name = app::create_migration(name).map_err(|e| CliError::MigrationCreateFailed { source: e })?;
    println!("Created new migration file: {file_name}");
    Ok(())
}

#[allow(clippy::unnecessary_wraps)]
fn migrate_action_list() -> Result<(), CliError> {
    let migrations = app::list_migrations();
    if migrations.is_empty() {
        println!("No migrations found.");
    } else {
        println!("Available migrations:");
        for (i, migration) in migrations.iter().enumerate() {
            println!("{i}. {migration}");
        }
    }
    Ok(())
}

async fn migrate_action_status(ctx: &common::ArcContext) -> Result<(), CliError> {
    match app::check_pending_migrations(&ctx.db).await {
        Ok(true) => println!("There are pending migrations that need to be applied."),
        Ok(false) => println!("Database is up to date. No pending migrations."),
        Err(app::MigrationError::NoMigrationsApplied) => println!("No migrations have been applied yet."),
        Err(e) => return Err(CliError::MigrationStatusCheckFailed { source: e }),
    }
    Ok(())
}

async fn migrate_action_run(ctx: &common::ArcContext) -> Result<(), CliError> {
    app::run_migrations(ctx)
        .await
        .map_err(|e| CliError::MigrationRunFailed { source: e })?;
    println!("Migrations applied successfully.");
    Ok(())
}

async fn create_admin(email: String, ctx: &common::ArcContext) -> Result<(), CliError> {
    // prompt for password securely
    print!("Enter password for admin user '{email}': ");
    io::stdout().flush()?;

    let password = rpassword::read_password()?;
    password
        .trim()
        .is_empty()
        .then(|| CliError::Other("Password cannot be empty".to_string()))
        .map_or(Ok(()), Err)?;

    let password_hash = auth::hash_password(&password)?;
    db::update_user_email_and_password(&ctx.db, 0, &email, &password_hash)
        .await
        .map_err(|e| CliError::Other(e.to_string()))?;

    println!("Admin user updated successfully.");
    Ok(())
}
