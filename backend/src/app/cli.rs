use std::io;
use std::io::Write;

use clap::{Parser, Subcommand};

use crate::app;
use crate::auth;
use crate::core;
use crate::db;

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

// TODO: add support for secret rotation (should mark all tokens as invalid)
#[derive(Subcommand)]
enum CliCommand {
    /// Run database migrations
    Migrate {
        #[command(subcommand)]
        action: MigrateAction,
    },

    /// Create an admin user
    CreateAdmin {
        /// Username for the admin user
        #[arg(short, long)]
        username: String,

        /// Email for the admin user (optional)
        #[arg(short, long)]
        email: Option<String>,
    },
}

#[derive(Subcommand)]
enum MigrateAction {
    /// Create a new migration file
    Create { name: String },

    /// List all available migrations
    List,

    /// Check if there are pending migrations
    Status,

    /// Run all pending migrations
    Run,
}

#[allow(clippy::unit_arg)]
pub async fn run_cli(db: &core::DbContext) -> Result<(), CliError> {
    let cli = Cli::parse();
    match cli.command {
        None => Ok(tracing::info!("CLI command not provided. Use --help for CLI usage.")),
        Some(CliCommand::Migrate { action }) => exec_migrate_command(action, db).await,
        Some(CliCommand::CreateAdmin { username, email }) => create_admin(username, email, db).await,
    }
}

async fn exec_migrate_command(action: MigrateAction, db: &core::DbContext) -> Result<(), CliError> {
    match action {
        MigrateAction::Create { name } => migrate_action_create(&name)?,
        MigrateAction::List => migrate_action_list(),
        MigrateAction::Status => migrate_action_status(db).await?,
        MigrateAction::Run => migrate_action_run(db).await?,
    }
    std::process::exit(0); // Exit the process since this is a CLI command
}

fn migrate_action_create(name: &str) -> Result<(), CliError> {
    let file_name = app::create_migration(name)
        .map_err(|e| CliError::MigrationCreateFailed { source: e })?;
    println!("Created new migration file: {file_name}");
    Ok(())
}

fn migrate_action_list() {
    let migrations = app::list_migrations();
    if migrations.is_empty() {
        println!("No migrations found.");
    } else {
        println!("Available migrations:");
        for (i, migration) in migrations.iter().enumerate() {
            println!("{i}. {migration}");
        }
    }
}

async fn migrate_action_status(db: &core::DbContext) -> Result<(), CliError> {
    match app::check_pending_migrations(db).await {
        Ok(true) => println!("There are pending migrations that need to be applied."),
        Ok(false) => println!("Database is up to date. No pending migrations."),
        Err(app::MigrationError::NoMigrationsApplied) => println!("No migrations have been applied yet."),
        Err(e) => return Err(CliError::MigrationStatusCheckFailed { source: e }),
    }
    Ok(())
}

async fn migrate_action_run(db: &core::DbContext) -> Result<(), CliError> {
    app::run_migrations(db)
        .await
        .map_err(|e| CliError::MigrationRunFailed { source: e })?;
    println!("Migrations applied successfully.");
    Ok(())
}

async fn create_admin(username: String, email: Option<String>, db: &core::DbContext) -> Result<(), CliError> {
    // Prompt for password securely
    print!("Enter password for admin user '{username}': ");
    io::stdout().flush().unwrap();

    let password = rpassword::read_password().map_err(|e| CliError::Other(e.to_string()))?;

    password
        .trim()
        .is_empty()
        .then(|| CliError::Other("Password cannot be empty".to_string()))
        .map_or(Ok(()), Err)?;

    // Check if user already exists; if found, return an error
    match db::get_user_by_name(db, &username).await {
        Err(core::DbError::RowNotFound) => Ok(()),
        Err(e) => Err(CliError::Other(e.to_string())),
        Ok(_) => Err(CliError::Other("User already exists".to_string())),
    }?;

    let password_hash = auth::hash_password(&password)
        .map_err(|_| CliError::Other("Failed to hash password".to_string()))?;
    let new_user = db::NewUser {
        username,
        password_hash: Some(password_hash),
        email,
        tenant_id: Some(1), // Default tenant
        sso_provider: None,
        sso_id: None,
    };

    db::create_user(db, new_user)
        .await
        .map_err(|e| CliError::Other(e.to_string()))?;

    println!("Admin user created successfully.");
    Ok(())
}
