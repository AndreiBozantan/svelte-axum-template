use std::env;
use std::fs;
use std::net::TcpStream;
use std::path::Path;
use std::process::{Command, ExitStatus};
use std::thread;
use std::time::Duration;

mod checks;
mod database;
mod docker;
mod status;
mod stop;

fn main() {
    let args: Vec<String> = env::args().collect();
    let task = args.get(1).map(String::as_str).unwrap_or("help");

    match task {
        "clean" => clean(),
        "status" => {
            let refresh =
                args.get(2).map(String::as_str) == Some("--refresh") || args.get(2).map(String::as_str) == Some("-r");
            let refresh_silent = args.get(2).map(String::as_str) == Some("--refresh-silent");
            status::status(refresh, refresh_silent);
        },
        "release" => release(),
        "lint-security" => {
            lint_security().expect("failed to run semgrep");
        },
        "db-create" => {
            database::db_create().expect("failed to create database");
        },
        "db-migrate" => {
            database::db_migrate().expect("failed to run migrations");
        },
        "db-prepare" => {
            database::db_prepare().expect("failed to prepare sqlx queries");
        },
        "db-prepare-check" => {
            database::db_prepare_check().expect("failed to check sqlx queries");
        },
        "db-drop" => {
            database::db_drop().expect("failed to drop database");
        },
        "db-init" => database::db_init(),
        "db-reset" => database::db_reset(),
        "dev-init" => dev_init(),
        "setup-hooks" => {
            checks::setup_hooks().expect("failed to set up git hooks");
        },
        "pre-commit" => {
            checks::pre_commit().expect("failed to run pre-commit checks");
        },
        "pre-push" => {
            checks::pre_push().expect("failed to run pre-push checks");
        },
        "ci-backend" => {
            checks::ci_backend().expect("failed to run CI backend checks");
        },
        "ci-frontend" => {
            checks::ci_frontend().expect("failed to run CI frontend checks");
        },
        "dev" => dev(),
        "docker-build" => {
            docker::docker_build().expect("failed to build docker image");
        },
        "docker-run" => {
            docker::docker_run().expect("failed to run docker container");
        },
        "docker-down" => {
            docker::docker_down().expect("failed to stop docker container");
        },
        "docker-debug" => {
            docker::docker_debug().expect("failed to run docker debug container");
        },
        "stop" => stop::stop(),
        _ => print_help(),
    }
}

fn print_help() {
    println!(
        r#"Svelaxum Xtask Runner

Available commands:
  clean            - Deletes build files, target, .sqlx, and node_modules
  status           - Displays project development status (branch, DB, services, tests, clippy, size)
  release          - Builds the frontend and backend in release mode
  lint-security    - Runs semgrep security scan
  db-init          - Installs sqlx-cli if missing, creates DB, runs migrations, and prepares queries
  db-create        - Creates the SQLite database
  db-migrate       - Runs database migrations
  db-prepare       - Prepares SQLx offline metadata (.sqlx/)
  db-prepare-check - Checks if SQLx offline metadata (.sqlx/) is up to date
  db-drop          - Drops the SQLite database
  db-reset         - Drops database and re-initializes it
  dev-init         - Installs frontend packages, initializes DB, and seeds admin user
  setup-hooks      - Sets up workspace git hooks
  ci-backend       - Runs all backend CI checks (fmt, clippy, sqlx, tests)
  ci-frontend      - Runs all frontend CI checks (prettier, svelte-check, tests, build)
  dev              - Runs backend watch and frontend dev server concurrently
  stop             - Stops any running backend servers
  docker-build     - Builds the production Docker image (svelaxum:release)
  docker-run       - Runs the production Docker container locally
  docker-down      - Stops and removes the production Docker container
  docker-debug     - Runs a debug container mounting the data volume"#
    );
}

pub(crate) fn run_command(
    cmd: &str,
    args: &[&str],
    dir: Option<&str>,
) -> std::io::Result<ExitStatus> {
    let mut command = Command::new(cmd);
    command.args(args);
    if let Some(d) = dir {
        command.current_dir(d);
    }
    command.status()
}

fn clean() {
    println!("Cleaning build artifacts and node_modules...");
    let targets = [
        "target",
        ".sqlx",
        "frontend/dist",
        "frontend/node_modules",
        "node_modules",
        "package-lock.json",
    ];
    for target in &targets {
        let path = Path::new(target);
        if path.exists() {
            if path.is_dir() {
                match fs::remove_dir_all(path) {
                    Ok(_) => println!("Removed directory: {}", target),
                    Err(e) => eprintln!("Failed to remove directory {}: {}", target, e),
                }
            } else {
                match fs::remove_file(path) {
                    Ok(_) => println!("Removed file: {}", target),
                    Err(e) => eprintln!("Failed to remove file {}: {}", target, e),
                }
            }
        }
    }
    println!("Clean completed.");
}

fn dev_init() {
    println!("Initializing development environment...");
    database::ensure_cargo_watch();

    // Set up git hooks
    checks::setup_hooks().expect("failed to set up git hooks");

    // Install frontend dependencies
    println!("Installing frontend dependencies...");
    let status = run_command("npm", &["install"], Some("frontend"));
    if status.is_err() || !status.unwrap().success() {
        eprintln!("Failed to install frontend dependencies.");
        std::process::exit(1);
    }

    // Build frontend once so that rust-embed has files
    println!("Building frontend...");
    let status = run_command("npm", &["run", "build"], Some("frontend"));
    if status.is_err() || !status.unwrap().success() {
        eprintln!("Failed to build frontend.");
        std::process::exit(1);
    }

    // Initialize database
    database::db_init();

    // Seed admin user
    println!("Seeding default admin user...");
    let status = run_command(
        "cargo",
        &["run", "--package", "app", "--", "create-admin", "--email", "a@b.cc"],
        None,
    );
    if status.is_err() || !status.unwrap().success() {
        eprintln!("Failed to seed admin user.");
        std::process::exit(1);
    }
    println!("Development environment initialized successfully!");
}

fn wait_for_port(port: u16) {
    let addr = format!("127.0.0.1:{}", port);
    println!("Waiting for port {} to open...", port);
    for _ in 0..150 {
        if TcpStream::connect(&addr).is_ok() {
            println!("Port {} is open.", port);
            return;
        }
        thread::sleep(Duration::from_millis(200));
    }
    eprintln!("Timeout waiting for port {}.", port);
}

fn dev() {
    database::ensure_cargo_watch();

    // Check if database exists, if not initialize it
    if !Path::new("data/db.sqlite").exists() {
        println!("Database not found. Initializing...");
        database::db_init();
    }

    // Check if frontend node_modules exists, if not install dependencies
    if !Path::new("frontend/node_modules").exists() {
        println!("Frontend node_modules not found. Installing...");
        let status = run_command("npm", &["install"], Some("frontend"));
        if status.is_err() || !status.unwrap().success() {
            eprintln!("Failed to install frontend dependencies.");
            std::process::exit(1);
        }
    }

    println!("Starting backend development watch server...");
    let mut backend = Command::new("cargo")
        .args([
            "watch",
            "--ignore",
            "data/db.sqlite",
            "--watch",
            "backend",
            "--exec",
            "run --package app",
        ])
        .spawn()
        .expect("failed to start backend watch");

    // Wait for backend to start up before starting frontend dev server
    wait_for_port(3000);

    println!("Starting frontend dev server...");
    let mut frontend = Command::new("npm")
        .args(["run", "dev"])
        .current_dir("frontend")
        .spawn()
        .expect("failed to start frontend dev server");

    // Wait for frontend dev server
    wait_for_port(5173);

    // Monitor processes
    loop {
        if let Ok(Some(status)) = backend.try_wait() {
            println!("Backend server exited with: {}", status);
            let _ = frontend.kill();
            break;
        }
        if let Ok(Some(status)) = frontend.try_wait() {
            println!("Frontend server exited with: {}", status);
            let _ = backend.kill();
            break;
        }
        thread::sleep(Duration::from_millis(500));
    }
}

fn release() {
    println!("Building frontend and backend in release mode...");

    // 1. Install frontend dependencies
    println!("Installing frontend dependencies...");
    let status = run_command("npm", &["install"], Some("frontend"));
    if status.is_err() || !status.unwrap().success() {
        eprintln!("Failed to install frontend dependencies.");
        std::process::exit(1);
    }

    // 2. Build frontend
    println!("Building frontend...");
    let status = run_command("npm", &["run", "build"], Some("frontend"));
    if status.is_err() || !status.unwrap().success() {
        eprintln!("Failed to build frontend.");
        std::process::exit(1);
    }

    // 3. Initialize database and offline query cache
    database::db_init();

    // 4. Build backend in release mode
    println!("Building backend in release mode...");
    let status = run_command("cargo", &["build", "--release"], None);
    if status.is_err() || !status.unwrap().success() {
        eprintln!("Failed to build backend.");
        std::process::exit(1);
    }
    println!("Release build completed successfully!");
}

fn lint_security() -> std::io::Result<ExitStatus> {
    println!("Running Semgrep security scan...");
    run_command("semgrep", &["--config", "r/all"], None)
}
