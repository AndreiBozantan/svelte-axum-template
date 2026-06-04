use std::io;
use std::io::Write;

use clap::Parser;
use clap::Subcommand;

use crate::common::ArcContext;
use crate::identity::auth::util;
use crate::identity::users::repo::SqliteUserRepo;
use crate::identity::users::service::{Email, UpdateAdminCredentialsCommand, UserId, UserService};
use crate::migrations;

#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error("Migration creation failed")]
    MigrationCreateFailed { source: migrations::MigrationError },

    #[error("Checking migration status failed")]
    MigrationStatusCheckFailed { source: migrations::MigrationError },

    #[error("Running migrations failed")]
    MigrationRunFailed { source: migrations::MigrationError },

    #[error("Password hashing failed")]
    PasswordHashFailed {
        #[from]
        source: argon2::password_hash::Error,
    },

    #[error("Failed to read password input")]
    PasswordReadFailed {
        #[from]
        source: std::io::Error,
    },

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
    Migrate {
        #[command(subcommand)]
        action: MigrateAction,
    },
    CreateAdmin {
        #[arg(short, long)]
        email: String,
    },
}

#[derive(Subcommand)]
enum MigrateAction {
    Create { name: String },
    List,
    Status,
    Run,
}

#[allow(clippy::unit_arg)]
pub async fn run_cli(ctx: &ArcContext) -> Result<bool, CliError> {
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

async fn exec_migrate_command(action: MigrateAction, ctx: &ArcContext) -> Result<(), CliError> {
    match action {
        MigrateAction::Create { name } => migrate_action_create(&name),
        MigrateAction::List => migrate_action_list(),
        MigrateAction::Status => migrate_action_status(ctx).await,
        MigrateAction::Run => migrate_action_run(ctx).await,
    }
}

fn migrate_action_create(name: &str) -> Result<(), CliError> {
    let file_name = migrations::create_migration(name).map_err(|e| CliError::MigrationCreateFailed { source: e })?;
    println!("Created new migration file: {file_name}");
    Ok(())
}

#[allow(clippy::unnecessary_wraps)]
fn migrate_action_list() -> Result<(), CliError> {
    let migrations = migrations::list_migrations();
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

async fn migrate_action_status(ctx: &ArcContext) -> Result<(), CliError> {
    match migrations::check_pending_migrations(&ctx.db).await {
        Ok(true) => println!("There are pending migrations that need to be applied."),
        Ok(false) => println!("Database is up to date. No pending migrations."),
        Err(migrations::MigrationError::NoMigrationsApplied) => println!("No migrations have been applied yet."),
        Err(e) => return Err(CliError::MigrationStatusCheckFailed { source: e }),
    }
    Ok(())
}

async fn migrate_action_run(ctx: &ArcContext) -> Result<(), CliError> {
    migrations::run_migrations(ctx)
        .await
        .map_err(|e| CliError::MigrationRunFailed { source: e })?;
    println!("Migrations applied successfully.");
    Ok(())
}

async fn create_admin(email: String, ctx: &ArcContext) -> Result<(), CliError> {
    print!("Enter password for admin user '{email}': ");
    io::stdout().flush()?;

    let password = rpassword::read_password()?;
    if password.trim().is_empty() {
        return Err(CliError::Other("Password cannot be empty".to_string()));
    }

    let password_hash = util::hash_password(password.trim())?;
    let parsed_email = Email::parse(&email).map_err(|e| CliError::Other(e.to_string()))?;

    UserService::new(SqliteUserRepo)
        .update_admin_credentials(
            &ctx.db,
            UpdateAdminCredentialsCommand {
                user_id: UserId(0),
                email: parsed_email,
                password_hash,
            },
        )
        .await
        .map_err(|e| CliError::Other(e.to_string()))?;

    println!("Admin user updated successfully.");
    Ok(())
}
