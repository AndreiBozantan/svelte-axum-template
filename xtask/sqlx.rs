use std::fs;
use std::process::{Command, ExitStatus};

fn ensure_sqlx_cli() {
    let sqlx_installed = Command::new("cargo")
        .args(["sqlx", "--version"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if !sqlx_installed {
        println!("sqlx-cli is not installed. Installing it via cargo-binstall...");
        let status = Command::new("cargo")
            .args(["binstall", "sqlx-cli", "--no-confirm"])
            .status();
        if status.is_err() || !status.unwrap().success() {
            eprintln!("cargo-binstall failed. Falling back to cargo install sqlx-cli...");
            let status2 = Command::new("cargo")
                .args(["install", "sqlx-cli", "--no-default-features", "--features", "sqlite"])
                .status();
            if status2.is_err() || !status2.unwrap().success() {
                eprintln!("Error: failed to install sqlx-cli. Please install it manually.");
                std::process::exit(1);
            }
        }
    }
}

pub fn ensure_cargo_watch() {
    let watch_installed = Command::new("cargo")
        .args(["watch", "--version"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if !watch_installed {
        println!("cargo-watch is not installed. Installing it via cargo-binstall...");
        let status = Command::new("cargo")
            .args(["binstall", "cargo-watch", "--no-confirm"])
            .status();
        if status.is_err() || !status.unwrap().success() {
            eprintln!("cargo-binstall failed. Falling back to cargo install cargo-watch...");
            let status2 = Command::new("cargo").args(["install", "cargo-watch"]).status();
            if status2.is_err() || !status2.unwrap().success() {
                eprintln!("Error: failed to install cargo-watch. Please install it manually.");
                std::process::exit(1);
            }
        }
    }
}

pub fn create() -> std::io::Result<ExitStatus> {
    fs::create_dir_all("data")?;
    println!("Creating database...");
    crate::run_command("cargo", &["sqlx", "database", "create"], None)
}

pub fn migrate() -> std::io::Result<ExitStatus> {
    println!("Running migrations...");
    crate::run_command("cargo", &["sqlx", "migrate", "run", "--source", "migrations"], None)
}

pub fn prepare() -> std::io::Result<ExitStatus> {
    println!("Preparing SQLx offline queries metadata...");
    crate::run_command(
        "cargo",
        &[
            "sqlx",
            "prepare",
            "--workspace",
            "--",
            "--all-targets",
            "--all-features",
        ],
        None,
    )
}

pub fn check_sqlx_queries() -> std::io::Result<ExitStatus> {
    ensure_sqlx_cli();
    println!("Checking if SQLx offline queries metadata is up to date...");
    crate::run_command(
        "cargo",
        &[
            "sqlx",
            "prepare",
            "--check",
            "--workspace",
            "--",
            "--all-targets",
            "--all-features",
        ],
        None,
    )
}

pub fn drop() -> std::io::Result<ExitStatus> {
    println!("Dropping database...");
    crate::run_command("cargo", &["sqlx", "database", "drop", "-y"], None)
}

pub fn init() {
    ensure_sqlx_cli();
    create().expect("failed to create database");
    migrate().expect("failed to run migrations");
    prepare().expect("failed to prepare offline queries");
    println!("Database initialized successfully.");
}

pub fn reset() {
    let _ = drop();
    init();
}

pub fn run(args: &[String]) {
    let subcommand = args.get(2).map(String::as_str);
    match subcommand {
        Some("init") => init(),
        Some("reset") => reset(),
        Some("prepare") => {
            prepare().expect("failed to prepare sqlx queries");
        },
        Some("check") => {
            check_sqlx_queries().expect("failed to check sqlx queries");
        },
        _ => {
            println!("SQLx Utility Actions:");
            println!(
                "  cargo xtask sqlx init    - Installs sqlx-cli if missing, creates DB, runs migrations, and prepares queries"
            );
            println!("  cargo xtask sqlx reset   - Drops database and re-initializes it");
            println!("  cargo xtask sqlx prepare - Prepares SQLx offline metadata (.sqlx/)");
            println!("  cargo xtask sqlx check   - Checks if SQLx offline metadata (.sqlx/) is up to date");
            println!("\nError: Please specify a valid sqlx action.");
            std::process::exit(1);
        },
    }
}
