// cli.rs - CLI utility for database migrations
use std::env;
use std::path::Path;
use thiserror::Error;
use clap::{Parser, Subcommand};

use crate::db::{self, migrations::MigrationError}; // Import MigrationError directly

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
}

pub async fn run_migration_cli(db_pool: &db::DbPool) -> Result<(), CliError> {
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
            match db::migrations::check_pending(db_pool).await {
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
            let migrations_path = Path::new("./back_end/migrations");
            db::migrations::run(db_pool, migrations_path).await
                .map_err(|e| CliError::MigrationRunFailed { source: e })?;
            println!("Migrations applied successfully.");
        },
    }

    // Exit the process since this is a CLI command
    std::process::exit(0);
}