// cli.rs - CLI utility for database migrations
use std::env;
use std::io;
use std::io::Write;
use std::path::Path;
use thiserror::Error;
use clap::{Parser, Subcommand};

use crate::app;
use crate::auth;
use crate::db;
use crate::db::migrations::MigrationError;
use crate::db::schema::NewUser;

#[derive(Debug, Error)]
pub enum CliError {
    #[error("Migration creation failed")]
    MigrationCreateFailed { #[source] source: MigrationError },

    #[error("Listing migrations failed")]
    MigrationListFailed { #[source] source: MigrationError },

    // For the Status command, only actual errors from check_pending should be wrapped.
    // NoMigrationsApplied is handled as informational output.
    #[error("Checking migration status failed")]
    MigrationStatusCheckFailed { #[source] source: MigrationError },

    #[error("Running migrations failed")]
    MigrationRunFailed { #[source] source: MigrationError },

    // The Other(String) variant is kept as a fallback, though ideally all errors should be specific.
    #[error("An unexpected CLI error occurred: {0}")]
    Other(String),
}

#[derive(Parser)]
#[command(name = "migrate")]
#[command(about = "Database migration utility", long_about = None)]
struct Cli {
    #[command(subcommand)]
    migrate_sub_command: MigrateSubCommands,
}

#[derive(Subcommand)]
enum MigrateSubCommands {
    /// Create a new migration file
    Create {
        /// Name of the migration
        name: String,
    },
    /// List all available migrations
    List,
    /// Check if there are pending migrations
    Status,
    /// Run all pending migrations
    Run,
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

pub async fn run_migration_cli(context: &app::Context) -> Result<(), CliError> {
    let args: Vec<String> = env::args().collect();

    // Only run if this is explicitly called with the right arguments
    if args.len() < 2 || args[1] != "migrate" {
        return Ok(());
    }

    // Rewrite args for clap to parse correctly (remove the "migrate" argument)
    let mut cli_args = vec![args[0].clone()];
    cli_args.extend(args.iter().skip(2).cloned());

    let cli = Cli::parse_from(cli_args);

    match cli.migrate_sub_command {
        MigrateSubCommands::Create { name } => {
            let filename = db::migrations::create(&name)
                .map_err(|e| CliError::MigrationCreateFailed { source: e })?;
            println!("Created new migration file: {filename}");
        },
        MigrateSubCommands::List => {
            let migrations = db::migrations::list()
                .map_err(|e| CliError::MigrationListFailed { source: e })?;
            if migrations.is_empty() {
                println!("No migrations found.");
            } else {
                println!("Available migrations:");
                for (i, migration) in migrations.iter().enumerate() {
                    println!("{}. {}", i + 1, migration);
                }
            }
        },
        MigrateSubCommands::Status => {
            match db::migrations::check_pending(&context.store).await {
                Ok(true) => println!("There are pending migrations that need to be applied."),
                Ok(false) => println!("Database is up to date. No pending migrations."),
                Err(e) => {
                    if let MigrationError::NoMigrationsApplied = e {
                        println!("No migrations have been applied yet.");
                    } else {
                        // Propagate other MigrationErrors
                        return Err(CliError::MigrationStatusCheckFailed { source: e });
                    }
                }
            }
        },
        MigrateSubCommands::Run => {
            let migrations_path = Path::new("./backend/migrations");
            db::migrations::run(&context.store, migrations_path).await
                .map_err(|e| CliError::MigrationRunFailed { source: e })?;
            println!("Migrations applied successfully.");
        },
        MigrateSubCommands::CreateAdmin { username, email } => {
            // Prompt for password securely
            print!("Enter password for admin user '{}': ", username);
            io::stdout().flush().unwrap();
            let password = rpassword::read_password().map_err(|e| CliError::Other(e.to_string()))?;

            if password.trim().is_empty() {
                return Err(CliError::Other("Password cannot be empty".to_string()));
            }

            create_admin_user(&context.store, &username, &password, email.as_deref()).await
                .map_err(|e| CliError::Other(e.to_string()))?;

            println!("Admin user '{}' created successfully!", username);
        },

    }

    // Exit the process since this is a CLI command
    std::process::exit(0);
}

async fn create_admin_user(
    store: &db::Store,
    username: &str,
    password: &str,
    email: Option<&str>
) -> Result<(), Box<dyn std::error::Error>> {
    // Check if user already exists
    if store.get_user_by_username(username).await.is_ok() {
        return Err("User already exists".into());
    }

    let password_hash = auth::hash_password(password)?;
    let new_user = NewUser {
        username: username.to_string(),
        password_hash: Some(password_hash),
        email: email.map(|e| e.to_string()),
        tenant_id: Some(1), // Default tenant
        sso_provider: None,
        sso_id: None,
    };

    store.create_user(new_user).await?;
    Ok(())
}
