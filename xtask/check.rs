use crate::docs;
use crate::sqlx;
use std::fs;
use std::path::Path;
use std::process::Command;

pub fn setup_hooks() -> std::io::Result<()> {
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

pub fn check_backend_fmt() -> std::io::Result<()> {
    println!("Checking Rust formatting (cargo fmt)...");
    let status = crate::run_command("cargo", &["fmt", "--all", "--check"], None)?;
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    Ok(())
}

pub fn check_backend_lint() -> std::io::Result<()> {
    println!("Running Rust lints (cargo clippy)...");
    let status = crate::run_command(
        "cargo",
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--",
            "-D",
            "warnings",
        ],
        None,
    )?;
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    Ok(())
}

pub fn check_backend_sqlx() -> std::io::Result<()> {
    println!("Verifying SQLx offline query metadata...");
    let status = crate::run_command(
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
    )?;
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    Ok(())
}

pub fn check_backend_test() -> std::io::Result<()> {
    println!("Running Rust tests (cargo test)...");
    let status = crate::run_command(
        "cargo",
        &["test", "--workspace", "--all-targets", "--all-features"],
        None,
    )?;
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    Ok(())
}

pub fn check_frontend_fmt() -> std::io::Result<()> {
    println!("Checking frontend formatting (Prettier)...");
    let status = crate::run_command("npm", &["run", "format:check"], Some("frontend"))?;
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    Ok(())
}

pub fn check_frontend_lint() -> std::io::Result<()> {
    println!("Running frontend lints (ESLint)...");
    let status = crate::run_command("npm", &["run", "lint:check"], Some("frontend"))?;
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    Ok(())
}

pub fn check_frontend_diagnostics() -> std::io::Result<()> {
    println!("Checking frontend types (svelte-check)...");
    let status = crate::run_command("npm", &["run", "check"], Some("frontend"))?;
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }

    println!("Checking frontend types (tsc --noEmit)...");
    let status = crate::run_command("npm", &["run", "check:ts"], Some("frontend"))?;
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    Ok(())
}

pub fn check_frontend_test() -> std::io::Result<()> {
    println!("Running frontend tests (npm run test)...");
    let status = crate::run_command("npm", &["run", "test"], Some("frontend"))?;
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    Ok(())
}

pub fn check_frontend_build() -> std::io::Result<()> {
    println!("Building frontend (npm run build)...");
    let status = crate::run_command("npm", &["run", "build"], Some("frontend"))?;
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    Ok(())
}

pub fn check_backend_openapi_drift() -> std::io::Result<()> {
    println!("Checking for OpenAPI spec drift...");

    let output = Command::new("cargo")
        .args(["run", "--package", "app", "--quiet", "--", "export-openapi"])
        .output()?;

    if !output.status.success() {
        eprintln!("Error: backend failed to export OpenAPI spec.");
        std::process::exit(output.status.code().unwrap_or(1));
    }

    if let Err(e) = fs::write("openapi.json", &output.stdout) {
        eprintln!("Error: failed to write openapi.json: {e}");
        std::process::exit(1);
    }

    let status = Command::new("git")
        .args(["diff", "--exit-code", "openapi.json"])
        .status()?;

    if !status.success() {
        eprintln!(
            "Error: openapi.json is out of sync with backend code. Run 'cargo xtask make openapi' and commit the changes."
        );
        std::process::exit(1);
    }

    println!("OpenAPI spec is in sync.");
    Ok(())
}

pub fn check_frontend_openapi_drift() -> std::io::Result<()> {
    println!("Checking for frontend OpenAPI client drift...");

    let status = crate::run_command("node", &["scripts/generate-api.ts"], Some("frontend"))?;

    if !status.success() {
        eprintln!("Error: frontend API client generation failed.");
        std::process::exit(status.code().unwrap_or(1));
    }

    let diff_status = Command::new("git")
        .args(["diff", "--exit-code", "frontend/src/lib/generated/"])
        .status()?;

    if !diff_status.success() {
        eprintln!(
            "Error: frontend/src/lib/generated/ is out of sync with openapi.json. Run 'cargo xtask make openapi' and commit the changes."
        );
        std::process::exit(1);
    }

    println!("Frontend OpenAPI client is in sync.");
    Ok(())
}

pub fn backend() -> std::io::Result<()> {
    println!("Running all backend CI checks...");
    check_backend_fmt()?;
    check_backend_lint()?;
    // Note: check_backend_sqlx() is intentionally skipped in CI.
    // It requires a live database and sqlx-cli, neither available on the runner.
    // Stale/missing .sqlx/ files are already caught by clippy (SQLX_OFFLINE=true
    // makes the proc macros validate queries against the cached .sqlx/ files).
    check_backend_test()?;
    check_backend_openapi_drift()?;
    println!("All backend CI checks passed!");
    Ok(())
}

pub fn frontend() -> std::io::Result<()> {
    println!("Running all frontend CI checks...");
    check_frontend_fmt()?;
    check_frontend_lint()?;
    check_frontend_diagnostics()?;
    check_frontend_build()?;
    check_frontend_test()?;
    check_frontend_openapi_drift()?;
    println!("All frontend CI checks passed!");
    Ok(())
}

pub fn security() -> std::io::Result<()> {
    println!("Running Semgrep security scan...");
    let status = crate::run_command("semgrep", &["--config", "r/all"], None)?;
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    Ok(())
}

pub fn pre_commit() -> std::io::Result<()> {
    println!("Running pre-commit formatting and OpenAPI drift checks...");
    let files = get_staged_files()?;

    let mut has_backend = false;
    let mut has_frontend = false;
    let mut has_docs = false;

    if files.is_empty() {
        println!("No staged files found. Running all checks as fallback.");
        has_backend = true;
        has_frontend = true;
        has_docs = true;
    } else {
        for file in &files {
            if file.starts_with("backend/")
                || file.starts_with("xtask/")
                || file == "Cargo.toml"
                || file == "Cargo.lock"
                || file == "rustfmt.toml"
                || file == "openapi.json"
            {
                has_backend = true;
            }
            if file.starts_with("frontend/") || file == "openapi.json" {
                has_frontend = true;
            }
            if file.ends_with(".md") {
                has_docs = true;
            }
        }
    }

    if has_backend {
        check_backend_fmt()?;
        check_backend_openapi_drift()?;
    } else {
        println!("No backend changes detected. Skipping Rust formatting and spec drift check.");
    }

    if has_frontend {
        check_frontend_fmt()?;
        check_frontend_lint()?;
        check_frontend_openapi_drift()?;
    } else {
        println!("No frontend changes detected. Skipping frontend formatting and client drift check.");
    }

    if has_docs {
        crate::docs::check_links()?;
    } else {
        println!("No markdown changes detected. Skipping markdown link check.");
    }

    println!("All pre-commit checks passed!");
    Ok(())
}

pub fn pre_push() -> std::io::Result<()> {
    println!("Running intelligent pre-push checks (lints, tests, and drift)...");
    let files = get_pushed_files()?;

    let mut has_backend = false;
    let mut has_frontend = false;

    if files.is_empty() {
        println!("Could not determine diff or first push on new branch. Running all checks and tests as fallback.");
        has_backend = true;
        has_frontend = true;
    } else {
        for file in &files {
            if file.starts_with("backend/")
                || file.starts_with("xtask/")
                || file == "Cargo.toml"
                || file == "Cargo.lock"
                || file == "openapi.json"
            {
                has_backend = true;
            }
            if file.starts_with("frontend/") || file == "openapi.json" {
                has_frontend = true;
            }
        }
    }

    if has_backend {
        check_backend_lint()?;
        check_backend_sqlx()?;
        check_backend_test()?;
        check_backend_openapi_drift()?;
    } else {
        println!("No backend changes detected. Skipping Rust lints, tests, and spec drift check.");
    }

    if has_frontend {
        check_frontend_lint()?;
        check_frontend_diagnostics()?;
        check_frontend_test()?;
        check_frontend_openapi_drift()?;
    } else {
        println!("No frontend changes detected. Skipping frontend diagnostics, tests, and client drift check.");
    }

    println!("All lints, checks, tests, and drift checks passed!");
    Ok(())
}

pub fn run(args: &[String]) {
    let subcommand = args.get(2).map(String::as_str).unwrap_or("all");
    match subcommand {
        "backend" => {
            backend().expect("failed to run backend checks");
        },
        "frontend" => {
            frontend().expect("failed to run frontend checks");
        },
        "security" => {
            security().expect("failed to run security checks");
        },
        "docs" => {
            docs::check_links().expect("failed to check markdown links");
        },
        "sqlx" => {
            sqlx::check_sqlx_queries().expect("failed to check sqlx queries");
        },
        "commit" => {
            pre_commit().expect("failed to run pre-commit checks");
        },
        "push" => {
            pre_push().expect("failed to run pre-push checks");
        },
        "all" => {
            println!("Running all verification checks...");
            backend().expect("failed to run backend checks");
            frontend().expect("failed to run frontend checks");
            if let Err(e) = security() {
                eprintln!("Warning: semgrep security scan failed: {e}");
            }
            docs::check_links().expect("failed to check markdown links");
        },
        _ => {
            println!("CI Verification Actions:");
            println!("  cargo xtask check          - Runs all CI checks");
            println!("  cargo xtask check backend  - Runs all backend CI checks (fmt, clippy, tests, drift)");
            println!("  cargo xtask check frontend - Runs all frontend CI checks (prettier, typecheck, tests, build)");
            println!("  cargo xtask check security - Runs semgrep security scan");
            println!("  cargo xtask check docs     - Validates markdown relative links and heading anchors");
            println!("  cargo xtask check sqlx     - Checks if SQLx offline metadata is up to date (alias)");
            println!("  cargo xtask check commit   - Runs pre-commit formatting and OpenAPI drift checks");
            println!("  cargo xtask check push     - Runs intelligent pre-push checks (lints, tests, and drift)");
            println!("\nError: Please specify a valid check target.");
            std::process::exit(1);
        },
    }
}
