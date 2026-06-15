use std::env;
use std::fs;
use std::net::TcpStream;
use std::path::Path;
use std::process::{Command, ExitStatus};
use std::thread;
use std::time::Duration;

mod status;

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
            db_create().expect("failed to create database");
        },
        "db-migrate" => {
            db_migrate().expect("failed to run migrations");
        },
        "db-prepare" => {
            db_prepare().expect("failed to prepare sqlx queries");
        },
        "db-prepare-check" => {
            db_prepare_check().expect("failed to check sqlx queries");
        },
        "db-drop" => {
            db_drop().expect("failed to drop database");
        },
        "db-init" => db_init(),
        "db-reset" => db_reset(),
        "dev-init" => dev_init(),
        "setup-hooks" => {
            setup_hooks().expect("failed to set up git hooks");
        },
        "pre-commit" => {
            pre_commit().expect("failed to run pre-commit checks");
        },
        "pre-push" => {
            pre_push().expect("failed to run pre-push checks");
        },
        "dev" => dev(),
        "docker-build" => {
            docker_build().expect("failed to build docker image");
        },
        "docker-run" => {
            docker_run().expect("failed to run docker container");
        },
        "docker-down" => {
            docker_down().expect("failed to stop docker container");
        },
        "docker-debug" => {
            docker_debug().expect("failed to run docker debug container");
        },
        _ => print_help(),
    }
}

fn print_help() {
    println!(
        r#"Svelaxum Xtask Runner

Available commands:
  clean         - Deletes build files, target, .sqlx, and node_modules
  status        - Displays project development status (branch, DB, services, tests, clippy, size)
  release       - Builds the frontend and backend in release mode
  lint-security - Runs semgrep security scan
  db-init       - Installs sqlx-cli if missing, creates DB, runs migrations, and prepares queries
  db-create     - Creates the SQLite database
  db-migrate    - Runs database migrations
  db-prepare       - Prepares SQLx offline metadata (.sqlx/)
  db-prepare-check - Checks if SQLx offline metadata (.sqlx/) is up to date
  db-drop          - Drops the SQLite database
  db-reset      - Drops database and re-initializes it
  dev-init      - Installs frontend packages, initializes DB, and seeds admin user
  setup-hooks   - Sets up workspace git hooks
  dev           - Runs backend watch and frontend dev server concurrently
  docker-build  - Builds the production Docker image (svelaxum:release)
  docker-run    - Runs the production Docker container locally
  docker-down   - Stops and removes the production Docker container
  docker-debug  - Runs a debug container mounting the data volume"#
    );
}

fn run_command(
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

fn ensure_cargo_watch() {
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

fn db_create() -> std::io::Result<ExitStatus> {
    fs::create_dir_all("data")?;
    println!("Creating database...");
    run_command("cargo", &["sqlx", "database", "create"], None)
}

fn db_migrate() -> std::io::Result<ExitStatus> {
    println!("Running migrations...");
    run_command("cargo", &["sqlx", "migrate", "run", "--source", "migrations"], None)
}

fn db_prepare() -> std::io::Result<ExitStatus> {
    println!("Preparing SQLx offline queries metadata...");
    run_command("cargo", &["sqlx", "prepare", "--workspace"], None)
}

fn db_prepare_check() -> std::io::Result<ExitStatus> {
    ensure_sqlx_cli();
    println!("Checking if SQLx offline queries metadata is up to date...");
    run_command("cargo", &["sqlx", "prepare", "--check", "--workspace"], None)
}

fn db_drop() -> std::io::Result<ExitStatus> {
    println!("Dropping database...");
    run_command("cargo", &["sqlx", "database", "drop", "-y"], None)
}

fn db_init() {
    ensure_sqlx_cli();
    db_create().expect("failed to create database");
    db_migrate().expect("failed to run migrations");
    db_prepare().expect("failed to prepare offline queries");
    println!("Database initialized successfully.");
}

fn db_reset() {
    let _ = db_drop();
    db_init();
}

fn dev_init() {
    println!("Initializing development environment...");
    ensure_cargo_watch();

    // Set up git hooks
    setup_hooks().expect("failed to set up git hooks");

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
    db_init();

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

fn open_browser(url: &str) {
    println!("Opening {} in browser...", url);
    let (cmd, args) = if cfg!(target_os = "macos") {
        ("open", vec![url])
    } else if cfg!(target_os = "windows") {
        ("cmd", vec!["/c", "start", url])
    } else {
        if Command::new("xdg-open")
            .arg(url)
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            return;
        }
        ("python3", vec!["-m", "webbrowser", url])
    };
    let _ = Command::new(cmd).args(args).status();
}

fn dev() {
    ensure_cargo_watch();

    // Check if database exists, if not initialize it
    if !Path::new("data/db.sqlite").exists() {
        println!("Database not found. Initializing...");
        db_init();
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

    // Open browser
    open_browser("http://localhost:5173");

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

fn docker_build() -> std::io::Result<ExitStatus> {
    println!("Building production docker image via docker compose...");
    run_command("docker", &["compose", "build"], None)
}

fn docker_run() -> std::io::Result<ExitStatus> {
    println!("Running release container via docker compose...");
    run_command("docker", &["compose", "up", "-d"], None)
}

fn docker_down() -> std::io::Result<ExitStatus> {
    println!("Stopping and removing release container via docker compose...");
    run_command("docker", &["compose", "down"], None)
}

fn docker_debug() -> std::io::Result<ExitStatus> {
    println!("Starting debug container with data volume mounted...");
    run_command(
        "docker",
        &[
            "run",
            "--rm",
            "-it",
            "--mount",
            "type=volume,src=svelaxum-data,dst=/data",
            "debian:bookworm-slim",
            "bash",
        ],
        None,
    )
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
    db_init();

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

fn setup_hooks() -> std::io::Result<()> {
    let git_dir = Path::new(".git");
    if !git_dir.exists() {
        println!("Not a git repository (no .git folder found). Skipping hooks setup.");
        return Ok(());
    }

    let hooks_dir = git_dir.join("hooks");
    fs::create_dir_all(&hooks_dir)?;

    let hooks = ["pre-commit", "pre-push"];

    for hook in &hooks {
        let src = Path::new(".githooks").join(hook);
        let dst = hooks_dir.join(hook);

        if !src.exists() {
            println!("Source hook file .githooks/{} does not exist. Skipping.", hook);
            continue;
        }

        println!("Installing {} hook to .git/hooks/{}...", hook, hook);
        fs::copy(&src, &dst)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&dst)?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&dst, perms)?;
        }
    }

    println!("Git hooks installed successfully.");
    Ok(())
}

fn get_staged_files() -> std::io::Result<Vec<String>> {
    let output = Command::new("git").args(["diff", "--cached", "--name-only"]).output()?;
    if !output.status.success() {
        return Err(std::io::Error::other("failed to run git diff"));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect())
}

fn get_pushed_files() -> std::io::Result<Vec<String>> {
    // Try diffing against upstream @{u}
    let output = Command::new("git").args(["diff", "--name-only", "@{u}.."]).output();

    let stdout = match output {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).into_owned(),
        _ => {
            // Fallback: diff against origin/main or main
            let fallback_output = Command::new("git")
                .args(["diff", "--name-only", "origin/main.."])
                .output();
            match fallback_output {
                Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).into_owned(),
                _ => {
                    // If everything else fails, return empty vector to fall back to running all tests
                    return Ok(Vec::new());
                },
            }
        },
    };
    Ok(stdout
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect())
}

fn pre_commit() -> std::io::Result<()> {
    println!("Running intelligent pre-commit checks...");
    let files = get_staged_files()?;

    let mut has_backend = false;
    let mut has_frontend = false;

    if files.is_empty() {
        println!("No staged files found. Running all formatting and lint checks as fallback.");
        has_backend = true;
        has_frontend = true;
    } else {
        for file in &files {
            if file.starts_with("backend/")
                || file.starts_with("xtask/")
                || file == "Cargo.toml"
                || file == "Cargo.lock"
                || file == "rustfmt.toml"
            {
                has_backend = true;
            }
            if file.starts_with("frontend/") {
                has_frontend = true;
            }
        }
    }

    if has_backend {
        println!("Checking Rust formatting (cargo fmt)...");
        let status = run_command("cargo", &["fmt", "--check"], None)?;
        if !status.success() {
            std::process::exit(status.code().unwrap_or(1));
        }

        println!("Running Rust lints (cargo clippy)...");
        let status = run_command(
            "cargo",
            &["clippy", "--workspace", "--all-targets", "--", "-D", "warnings"],
            None,
        )?;
        if !status.success() {
            std::process::exit(status.code().unwrap_or(1));
        }

        println!("Verifying SQLx offline query metadata...");
        let status = run_command("cargo", &["sqlx", "prepare", "--check", "--workspace"], None)?;
        if !status.success() {
            std::process::exit(status.code().unwrap_or(1));
        }
    } else {
        println!("No backend changes detected. Skipping Rust lints and formatting.");
    }

    if has_frontend {
        println!("Checking frontend formatting (Prettier)...");
        let status = run_command("npm", &["run", "format:check"], Some("frontend"))?;
        if !status.success() {
            std::process::exit(status.code().unwrap_or(1));
        }

        println!("Checking frontend types (svelte-check)...");
        let status = run_command("npm", &["run", "check"], Some("frontend"))?;
        if !status.success() {
            std::process::exit(status.code().unwrap_or(1));
        }
    } else {
        println!("No frontend changes detected. Skipping frontend checks.");
    }

    println!("All pre-commit checks passed!");
    Ok(())
}

fn pre_push() -> std::io::Result<()> {
    println!("Running intelligent pre-push checks...");
    let files = get_pushed_files()?;

    let mut has_backend = false;
    let mut has_frontend = false;

    if files.is_empty() {
        println!("Could not determine diff or first push on new branch. Running all tests as fallback.");
        has_backend = true;
        has_frontend = true;
    } else {
        for file in &files {
            if file.starts_with("backend/")
                || file.starts_with("xtask/")
                || file == "Cargo.toml"
                || file == "Cargo.lock"
            {
                has_backend = true;
            }
            if file.starts_with("frontend/") {
                has_frontend = true;
            }
        }
    }

    if has_backend {
        println!("Running Rust tests (cargo test)...");
        let status = run_command("cargo", &["test", "--workspace"], None)?;
        if !status.success() {
            std::process::exit(status.code().unwrap_or(1));
        }
    } else {
        println!("No backend changes detected. Skipping Rust tests.");
    }

    if has_frontend {
        println!("Running frontend tests (npm run test)...");
        let status = run_command("npm", &["run", "test"], Some("frontend"))?;
        if !status.success() {
            std::process::exit(status.code().unwrap_or(1));
        }
    } else {
        println!("No frontend changes detected. Skipping frontend tests.");
    }

    println!("All tests passed!");
    Ok(())
}
