use crate::run_command;
use crate::sqlx;
use std::fs;
use std::path::Path;
use std::process::Command;

pub fn clean() {
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

pub fn openapi() {
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

pub fn release() {
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
    sqlx::init();

    // 4. Build backend in release mode
    println!("Building backend in release mode...");
    let status = run_command("cargo", &["build", "--release"], None);
    if status.is_err() || !status.unwrap().success() {
        eprintln!("Failed to build backend.");
        std::process::exit(1);
    }
    println!("Release build completed successfully!");
}

pub fn format() {
    println!("Formatting Rust codebase (cargo fmt)...");
    let status = run_command("cargo", &["fmt", "--all"], None);
    if status.is_err() || !status.unwrap().success() {
        eprintln!("Rust formatting failed.");
    }

    println!("Formatting frontend codebase (Prettier)...");
    let status = run_command("npm", &["run", "format"], Some("frontend"));
    if status.is_err() || !status.unwrap().success() {
        eprintln!("Frontend formatting failed.");
    }
}

pub fn run(args: &[String]) {
    let subcommand = args.get(2).map(String::as_str).unwrap_or("all");
    match subcommand {
        "backend" => {
            println!("Building backend in debug mode...");
            let status = run_command(
                "cargo",
                &["build", "--workspace", "--all-targets", "--all-features"],
                None,
            );
            if status.is_err() || !status.unwrap().success() {
                eprintln!("Backend build failed.");
                std::process::exit(1);
            }
        },
        "frontend" => {
            println!("Building frontend...");
            let status = run_command("npm", &["run", "build"], Some("frontend"));
            if status.is_err() || !status.unwrap().success() {
                eprintln!("Frontend build failed.");
                std::process::exit(1);
            }
        },
        "release" => {
            release();
        },
        "clean" => {
            clean();
        },
        "openapi" => {
            openapi();
        },
        "format" => {
            format();
        },
        "all" => {
            println!("Building frontend and backend in debug mode...");
            println!("Building frontend...");
            let status = run_command("npm", &["run", "build"], Some("frontend"));
            if status.is_err() || !status.unwrap().success() {
                eprintln!("Frontend build failed.");
                std::process::exit(1);
            }
            println!("Building backend in debug mode...");
            let status = run_command(
                "cargo",
                &["build", "--workspace", "--all-targets", "--all-features"],
                None,
            );
            if status.is_err() || !status.unwrap().success() {
                eprintln!("Backend build failed.");
                std::process::exit(1);
            }
        },
        _ => {
            println!("Workspace Make Actions:");
            println!("  cargo xtask make          - Builds frontend and backend in debug mode");
            println!("  cargo xtask make backend  - Builds backend in debug mode");
            println!("  cargo xtask make frontend - Builds frontend");
            println!("  cargo xtask make release  - Builds frontend and backend in release mode");
            println!("  cargo xtask make clean    - Deletes build files, target, .sqlx, and node_modules");
            println!("  cargo xtask make openapi  - Generates OpenAPI spec and frontend client");
            println!("  cargo xtask make format   - Auto-formats backend (cargo fmt) and frontend (prettier)");
            println!("\nError: Please specify a valid make action.");
            std::process::exit(1);
        },
    }
}
