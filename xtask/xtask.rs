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
mod lintmd;
mod status;
mod stop;

struct XtaskCommand {
    name: &'static str,
    description: &'static str,
    run: fn(args: &[String]),
}

const COMMANDS: &[XtaskCommand] = &[
    XtaskCommand {
        name: "clean",
        description: "Deletes build files, target, .sqlx, and node_modules",
        run: |_| clean(),
    },
    XtaskCommand {
        name: "status",
        description: "Displays project development status (branch, DB, services, tests, clippy, size)",
        run: |args| {
            let refresh =
                args.get(2).map(String::as_str) == Some("--refresh") || args.get(2).map(String::as_str) == Some("-r");
            let refresh_silent = args.get(2).map(String::as_str) == Some("--refresh-silent");
            status::status(refresh, refresh_silent);
        },
    },
    XtaskCommand {
        name: "release",
        description: "Builds the frontend and backend in release mode",
        run: |_| release(),
    },
    XtaskCommand {
        name: "lint-security",
        description: "Runs semgrep security scan",
        run: |_| {
            lint_security().expect("failed to run semgrep");
        },
    },
    XtaskCommand {
        name: "db-init",
        description: "Installs sqlx-cli if missing, creates DB, runs migrations, and prepares queries",
        run: |_| database::db_init(),
    },
    XtaskCommand {
        name: "db-create",
        description: "Creates the SQLite database",
        run: |_| {
            database::db_create().expect("failed to create database");
        },
    },
    XtaskCommand {
        name: "db-migrate",
        description: "Runs database migrations",
        run: |_| {
            database::db_migrate().expect("failed to run migrations");
        },
    },
    XtaskCommand {
        name: "db-prepare",
        description: "Prepares SQLx offline metadata (.sqlx/)",
        run: |_| {
            database::db_prepare().expect("failed to prepare sqlx queries");
        },
    },
    XtaskCommand {
        name: "db-prepare-check",
        description: "Checks if SQLx offline metadata (.sqlx/) is up to date",
        run: |_| {
            database::db_prepare_check().expect("failed to check sqlx queries");
        },
    },
    XtaskCommand {
        name: "db-drop",
        description: "Drops the SQLite database",
        run: |_| {
            database::db_drop().expect("failed to drop database");
        },
    },
    XtaskCommand {
        name: "db-reset",
        description: "Drops database and re-initializes it",
        run: |_| database::db_reset(),
    },
    XtaskCommand {
        name: "dev-init",
        description: "Installs frontend packages, initializes DB, and seeds admin user",
        run: |_| dev_init(),
    },
    XtaskCommand {
        name: "setup-hooks",
        description: "Sets up workspace git hooks",
        run: |_| {
            checks::setup_hooks().expect("failed to set up git hooks");
        },
    },
    XtaskCommand {
        name: "pre-commit",
        description: "Runs pre-commit checks (formatting, clippy, sqlx, svelte-check, prettier)",
        run: |_| {
            checks::pre_commit().expect("failed to run pre-commit checks");
        },
    },
    XtaskCommand {
        name: "pre-push",
        description: "Runs pre-push checks (backend/frontend tests)",
        run: |_| {
            checks::pre_push().expect("failed to run pre-push checks");
        },
    },
    XtaskCommand {
        name: "ci-backend",
        description: "Runs all backend CI checks (fmt, clippy, sqlx, tests)",
        run: |_| {
            checks::ci_backend().expect("failed to run CI backend checks");
        },
    },
    XtaskCommand {
        name: "ci-frontend",
        description: "Runs all frontend CI checks (prettier, svelte-check, tests, build)",
        run: |_| {
            checks::ci_frontend().expect("failed to run CI frontend checks");
        },
    },
    XtaskCommand {
        name: "check-md-links",
        description: "Validates relative markdown links and heading anchors across the repo",
        run: |_| lintmd::check_md_links().expect("failed to check markdown links"),
    },
    XtaskCommand {
        name: "dev",
        description: "Runs backend watch and frontend dev server concurrently",
        run: |_| dev(),
    },
    XtaskCommand {
        name: "openapi",
        description: "Generates OpenAPI spec and frontend TypeScript client",
        run: |_| openapi(),
    },
    XtaskCommand {
        name: "stop",
        description: "Stops any running backend servers",
        run: |_| stop::stop(),
    },
    XtaskCommand {
        name: "docker-build",
        description: "Builds the production Docker image (svelaxum:release)",
        run: |_| {
            docker::docker_build().expect("failed to build docker image");
        },
    },
    XtaskCommand {
        name: "docker-run",
        description: "Runs the production Docker container locally",
        run: |_| {
            docker::docker_run().expect("failed to run docker container");
        },
    },
    XtaskCommand {
        name: "docker-down",
        description: "Stops and removes the production Docker container",
        run: |_| {
            docker::docker_down().expect("failed to stop docker container");
        },
    },
    XtaskCommand {
        name: "docker-debug",
        description: "Runs a debug container mounting the data volume",
        run: |_| {
            docker::docker_debug().expect("failed to run docker debug container");
        },
    },
];

fn main() {
    let args: Vec<String> = env::args().collect();
    let task_name = args.get(1).map(String::as_str).unwrap_or("help");

    if task_name == "help" || task_name == "--help" || task_name == "-h" {
        print_help();
        return;
    }

    if let Some(cmd) = COMMANDS.iter().find(|c| c.name == task_name) {
        (cmd.run)(&args);
    } else {
        eprintln!("Unknown command: {}", task_name);
        println!();
        print_help();
        std::process::exit(1);
    }
}

fn print_help() {
    println!("Svelaxum Xtask Runner\n");
    println!("Available commands:");
    let max_len = COMMANDS.iter().map(|c| c.name.len()).max().unwrap_or(0);
    for cmd in COMMANDS {
        println!("  {:width$} - {}", cmd.name, cmd.description, width = max_len);
    }
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
            "--quiet",
            "--ignore",
            "data/db.sqlite",
            "--watch",
            "backend",
            "--exec",
            "run --package app --features swagger",
        ])
        .spawn()
        .expect("failed to start backend watch");

    // Wait for backend to start up before starting frontend dev server
    wait_for_port(3000);

    println!("Starting frontend dev server...");
    let mut frontend = Command::new("npm")
        .args(["run", "dev"])
        .current_dir("frontend")
        .stdin(std::process::Stdio::null())
        .spawn()
        .expect("failed to start frontend dev server");

    // Wait for frontend dev server
    wait_for_port(5173);

    // Monitor processes
    loop {
        if let Ok(Some(status)) = backend.try_wait() {
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                if let Some(sig) = status.signal() {
                    if sig == 15 {
                        println!("Backend server stopped.");
                    } else {
                        println!("Backend server terminated by signal: {}", sig);
                    }
                } else {
                    println!("Backend server exited with status: {}", status);
                }
            }
            #[cfg(not(unix))]
            {
                println!("Backend server exited with: {}", status);
            }
            let _ = frontend.kill();
            break;
        }
        if let Ok(Some(status)) = frontend.try_wait() {
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                if let Some(sig) = status.signal() {
                    if sig == 15 {
                        println!("Frontend server stopped.");
                    } else {
                        println!("Frontend server terminated by signal: {}", sig);
                    }
                } else {
                    println!("Frontend server exited with status: {}", status);
                }
            }
            #[cfg(not(unix))]
            {
                println!("Frontend server exited with: {}", status);
            }
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

pub(crate) fn openapi() {
    println!("Generating OpenAPI JSON specification...");

    let output = Command::new("cargo")
        .args(["run", "--package", "app", "--quiet", "--", "export-openapi"])
        .output();

    let output = match output {
        Ok(out) => {
            if !out.status.success() {
                eprintln!("Error: backend failed to export OpenAPI spec.");
                std::process::exit(out.status.code().unwrap_or(1));
            }
            out
        },
        Err(e) => {
            eprintln!("Error: failed to execute cargo run: {e}");
            std::process::exit(1);
        },
    };

    if let Err(e) = fs::write("openapi.json", &output.stdout) {
        eprintln!("Error: failed to write openapi.json: {e}");
        std::process::exit(1);
    }
    println!("Saved OpenAPI JSON specification to openapi.json");

    println!("Generating frontend TypeScript client...");
    let status = run_command("node", &["scripts/generate-api.ts"], Some("frontend"));

    match status {
        Ok(st) => {
            if !st.success() {
                eprintln!("Error: frontend API client generation failed.");
                std::process::exit(st.code().unwrap_or(1));
            }
        },
        Err(e) => {
            eprintln!("Error: failed to execute npm run generate:api: {e}");
            std::process::exit(1);
        },
    }

    println!(
        "Successfully generated and formatted TypeScript client: frontend/src/lib/generated/api.d.ts and endpoints.ts"
    );
}
