// cli.rs - CLI utility for database migrations
use std::env;
use std::path::Path;
use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::db;

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

pub async fn run_migration_cli(db_pool: &db::DbPoolRef) -> Result<()> {
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
            let filename = db::migrations::create(&name)?;
            println!("Created new migration file: {filename}");
        },
        MigrateSubCommands::List => {
            let migrations = db::migrations::list()?;
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
            match db::migrations::check_pending(&db_pool).await {
                Ok(true) => println!("There are pending migrations that need to be applied."),
                Ok(false) => println!("Database is up to date. No pending migrations."),
                Err(e) => {
                    if e.to_string().contains("No migrations applied yet") {
                        println!("No migrations have been applied yet.");
                    } else {
                        return Err(e);
                    }
                }
            }
        },
        MigrateSubCommands::Run => {
            let migrations_path = Path::new("./back_end/migrations");
            db::migrations::run(&db_pool, migrations_path).await?;
            println!("Migrations applied successfully.");
        },
    }

    // Exit the process since this is a CLI command
    std::process::exit(0);
}