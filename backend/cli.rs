use std::io;
use std::io::Write;

use clap::Parser;
use clap::Subcommand;

use crate::platform::common;
use crate::platform::crypto;
use crate::platform::migrations;

use crate::platform::identity::users;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Migration creation failed")]
    MigrationCreationFailed { source: migrations::Error },

    #[error("Checking migration status failed")]
    MigrationStatusCheckFailed { source: migrations::Error },

    #[error("Running migrations failed")]
    MigrationRunFailed { source: migrations::Error },

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

    #[error("Database error occurred: {source}")]
    DatabaseOperationFailed {
        #[from]
        source: crate::platform::db::Error,
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
pub async fn run_cli(ctx: &common::ArcContext) -> Result<bool, Error> {
    let cli = Cli::parse();
    match cli.command {
        None => {
            tracing::info!("CLI command not provided. Use --help for CLI usage.");
            Ok(false)
        },
        Some(CliCommand::Migrate { action }) => {
            exec_migrate_command(action, ctx).await?;
            Ok(true)
        },
        Some(CliCommand::CreateAdmin { email }) => {
            create_admin(email, ctx).await?;
            Ok(true)
        },
    }
}

async fn exec_migrate_command(
    action: MigrateAction,
    ctx: &common::ArcContext,
) -> Result<(), Error> {
    match action {
        MigrateAction::Create { name } => migrate_action_create(&name),
        MigrateAction::List => migrate_action_list(),
        MigrateAction::Status => migrate_action_status(ctx).await,
        MigrateAction::Run => migrate_action_run(ctx).await,
    }
}

fn migrate_action_create(name: &str) -> Result<(), Error> {
    let file_name = migrations::create_migration(name).map_err(|e| Error::MigrationCreationFailed { source: e })?;
    println!("Created new migration file: {file_name}");
    Ok(())
}

#[allow(clippy::unnecessary_wraps)]
fn migrate_action_list() -> Result<(), Error> {
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

async fn migrate_action_status(ctx: &common::ArcContext) -> Result<(), Error> {
    match migrations::check_pending_migrations(&ctx.db).await {
        Ok(true) => println!("There are pending migrations that need to be applied."),
        Ok(false) => println!("Database is up to date. No pending migrations."),
        Err(migrations::Error::NoMigrationsApplied) => println!("No migrations have been applied yet."),
        Err(e) => return Err(Error::MigrationStatusCheckFailed { source: e }),
    }
    Ok(())
}

async fn migrate_action_run(ctx: &common::ArcContext) -> Result<(), Error> {
    migrations::run_migrations(ctx)
        .await
        .map_err(|e| Error::MigrationRunFailed { source: e })?;
    println!("Migrations applied successfully.");
    Ok(())
}

async fn create_admin(
    email: String,
    ctx: &common::ArcContext,
) -> Result<(), Error> {
    use crate::platform::identity::users::TRepository;

    print!("Enter password for admin user '{email}': ");
    io::stdout().flush()?;

    let password = rpassword::read_password()?;
    if password.trim().is_empty() {
        return Err(Error::Other("Password cannot be empty".to_string()));
    }

    let password_hash = crypto::hash_password(password.trim())?;
    let parsed_email = common::Email::parse(&email).ok_or_else(|| Error::Other("invalid email address".to_string()))?;

    users::db::Repository
        .update_admin_credentials(
            &ctx.db,
            users::UpdateAdminCredentialsCommand {
                user_id: common::UserId(0),
                email: parsed_email,
                password_hash,
            },
        )
        .await?;

    println!("Admin user updated successfully.");
    Ok(())
}
