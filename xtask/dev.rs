use std::env;
use std::fs;
use std::net::TcpStream;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use crate::check;
use crate::run_command;
use crate::sqlx;
use crate::status;

pub fn run(args: &[String]) {
    let subcommand = args.get(2).map(String::as_str);
    match subcommand {
        Some("run") => run_servers(),
        Some("down") => down(),
        Some("status") => {
            let refresh =
                args.get(3).map(String::as_str) == Some("--refresh") || args.get(3).map(String::as_str) == Some("-r");
            let refresh_silent = args.get(3).map(String::as_str) == Some("--refresh-silent");
            status::status(refresh, refresh_silent);
        },
        Some("init") => init(),
        Some("admin") => admin(args),
        None => {
            if is_running() {
                println!("Development servers are running. Bringing them down...");
                down();
            } else {
                println!("No development servers are running. Starting them...");
                run_servers();
            }
        },
        Some("--help") | Some("-h") | Some("help") => {
            print_help();
        },
        Some(other) => {
            eprintln!("Unknown dev subcommand: {}", other);
            println!();
            print_help();
            std::process::exit(1);
        },
    }
}

fn print_help() {
    println!("Workspace Dev Actions:");
    println!("  cargo xtask dev        - Runs dev environment if stopped, otherwise brings it down");
    println!("  cargo xtask dev run    - Runs backend watch and frontend dev server");
    println!("  cargo xtask dev down   - Stops any running backend or frontend servers");
    println!("  cargo xtask dev status - Displays project development status");
    println!("  cargo xtask dev init   - Installs frontend packages, initializes DB, and seeds admin");
    println!("  cargo xtask dev admin  - Creates/updates the admin user interactively");
}

pub fn init() {
    println!("Initializing development environment...");
    sqlx::ensure_cargo_watch();

    // Set up git hooks
    check::setup_hooks().expect("failed to set up git hooks");

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
    sqlx::init();

    // Seed admin user
    println!("Seeding default admin user...");
    let status = Command::new("cargo")
        .args(["run", "--quiet", "--package", "app", "--", "create-admin"])
        .env("APP__SERVER__ENV", "development")
        .status();
    if status.is_err() || !status.unwrap().success() {
        eprintln!("Failed to seed admin user.");
        std::process::exit(1);
    }
    println!("Development environment initialized successfully!");
}

pub fn admin(args: &[String]) {
    let mut run_args = vec!["run", "--quiet", "--package", "app", "--", "create-admin"];
    // Skip the first three arguments: ["xtask", "dev", "admin"]
    for arg in args.iter().skip(3) {
        run_args.push(arg);
    }
    let status = Command::new("cargo")
        .args(&run_args)
        .env("APP__SERVER__ENV", "development")
        .status();
    if status.is_err() || !status.unwrap().success() {
        eprintln!("Failed to create admin user.");
        std::process::exit(1);
    }
}

pub fn is_running() -> bool {
    !find_dev_pids().is_empty()
}

pub fn down() {
    println!("Finding running development servers...");
    let pids = find_dev_pids();
    if pids.is_empty() {
        println!("No running backend or frontend servers found.");
        return;
    }

    // Filter to only send SIGTERM to root-most processes to allow clean, warning-free signal propagation
    let mut root_pids = Vec::new();
    for &pid in &pids {
        let mut has_ancestor_in_list = false;
        let mut curr = pid;
        while let Some(ppid) = get_ppid(curr) {
            if ppid <= 1 {
                break;
            }
            if pids.contains(&ppid) {
                has_ancestor_in_list = true;
                break;
            }
            curr = ppid;
        }
        if !has_ancestor_in_list {
            root_pids.push(pid);
        }
    }

    println!("Stopping server processes (PIDs: {:?})...", root_pids);
    for pid in &root_pids {
        let mut kill_cmd = Command::new("kill");
        kill_cmd.arg(pid.to_string());
        kill_cmd.stderr(Stdio::null());
        kill_cmd.stdout(Stdio::null());
        let _ = kill_cmd.status();
    }

    thread::sleep(Duration::from_millis(500));

    let mut still_running = Vec::new();
    for pid in &pids {
        if Path::new(&format!("/proc/{}", pid)).exists() {
            still_running.push(*pid);
        }
    }

    if !still_running.is_empty() {
        println!("Forcibly killing remaining processes: {:?}", still_running);
        for pid in &still_running {
            let mut kill_cmd = Command::new("kill");
            kill_cmd.arg("-9").arg(pid.to_string());
            kill_cmd.stderr(Stdio::null());
            kill_cmd.stdout(Stdio::null());
            let _ = kill_cmd.status();
        }
    }

    println!("Development servers stopped.");
}

fn get_ppid(pid: u32) -> Option<u32> {
    let stat = fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    let rparen = stat.rfind(')')?;
    let after_rparen = &stat[rparen + 1..];
    let parts: Vec<&str> = after_rparen.split_whitespace().collect();
    if parts.len() >= 2 {
        parts[1].parse::<u32>().ok()
    } else {
        None
    }
}

fn get_comm(pid: u32) -> Option<String> {
    fs::read_to_string(format!("/proc/{}/comm", pid))
        .map(|s| s.trim().to_string())
        .ok()
}

fn get_cmdline(pid: u32) -> Option<String> {
    let content = fs::read(format!("/proc/{}/cmdline", pid)).ok()?;
    if content.is_empty() {
        return None;
    }
    let parts: Vec<String> = content
        .split(|&c| c == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect();
    if parts.is_empty() { None } else { Some(parts.join(" ")) }
}

fn find_dev_pids() -> Vec<u32> {
    let mut pids = Vec::new();

    let current_dir = env::current_dir().ok();
    let current_dir_str = current_dir.as_ref().and_then(|p| p.to_str());

    // 1. Check port 3000 (backend)
    if let Some(pid) = status::get_pid_for_port(3000) {
        if !pids.contains(&pid) {
            pids.push(pid);
        }

        let mut curr = pid;
        while let Some(ppid) = get_ppid(curr) {
            if ppid <= 1 {
                break;
            }
            if let Some(comm) = get_comm(ppid) {
                let comm_lower = comm.to_lowercase();
                if comm_lower == "fish"
                    || comm_lower == "bash"
                    || comm_lower == "zsh"
                    || comm_lower == "systemd"
                    || comm_lower == "init"
                {
                    break;
                }

                if (comm_lower == "cargo-watch" || comm_lower == "cargo" || comm_lower == "sh") && !pids.contains(&ppid)
                {
                    pids.push(ppid);
                }
            }
            curr = ppid;
        }
    }

    // 2. Check port 5173 (frontend)
    if let Some(pid) = status::get_pid_for_port(5173) {
        if !pids.contains(&pid) {
            pids.push(pid);
        }

        let mut curr = pid;
        while let Some(ppid) = get_ppid(curr) {
            if ppid <= 1 {
                break;
            }
            if let Some(comm) = get_comm(ppid) {
                let comm_lower = comm.to_lowercase();
                if comm_lower == "fish"
                    || comm_lower == "bash"
                    || comm_lower == "zsh"
                    || comm_lower == "systemd"
                    || comm_lower == "init"
                {
                    break;
                }

                if (comm_lower == "node" || comm_lower == "npm" || comm_lower == "sh") && !pids.contains(&ppid) {
                    pids.push(ppid);
                }
            }
            curr = ppid;
        }
    }

    // 3. Scan /proc for other backend/frontend/watch processes in this workspace
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if let Ok(pid) = name_str.parse::<u32>() {
                if pids.contains(&pid) {
                    continue;
                }

                let process_cwd = fs::read_link(format!("/proc/{}/cwd", pid)).ok();
                let process_cwd_str = process_cwd.as_ref().and_then(|p| p.to_str());

                let in_workspace = match (current_dir_str, process_cwd_str) {
                    (Some(curr), Some(proc_cwd)) => proc_cwd.starts_with(curr),
                    _ => false,
                };

                if in_workspace && let Some(comm) = get_comm(pid) {
                    let comm_lower = comm.to_lowercase();
                    let cmdline = get_cmdline(pid).unwrap_or_default();

                    let is_app = comm_lower == "app"
                        || cmdline.contains("target/debug/app")
                        || cmdline.contains("target/release/app");
                    let is_cargo_watch = comm_lower == "cargo-watch" || cmdline.contains("cargo-watch");
                    let is_cargo_run = comm_lower == "cargo"
                        && (cmdline.contains("run --package app") || cmdline.contains("run -p app"));
                    let is_node = comm_lower == "node" && (cmdline.contains("vite") || cmdline.contains("npm"));
                    let is_npm = comm_lower == "npm" && cmdline.contains("run dev");

                    if is_app || is_cargo_watch || is_cargo_run || is_node || is_npm {
                        pids.push(pid);
                    }
                }
            }
        }
    }

    pids
}

fn run_servers() {
    sqlx::ensure_cargo_watch();

    // Check if database exists, if not initialize it
    if !Path::new("data/db.sqlite").exists() {
        println!("Database not found. Initializing...");
        sqlx::init();
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
        .env("APP__SERVER__ENV", "development")
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

    // Wait for frontend dev server, then open the app in the browser
    if wait_for_port(crate::FRONTEND_PORT) {
        open_browser(&format!("http://localhost:{}", crate::FRONTEND_PORT));
    }

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

fn wait_for_port(port: u16) -> bool {
    let addr = format!("127.0.0.1:{}", port);
    println!("Waiting for port {} to open...", port);
    for _ in 0..150 {
        if TcpStream::connect(&addr).is_ok() {
            println!("Port {} is open.", port);
            return true;
        }
        thread::sleep(Duration::from_millis(200));
    }
    eprintln!("Timeout waiting for port {}.", port);
    false
}

// devcontainers set $BROWSER to a helper that opens URLs in the host browser
fn open_browser(url: &str) {
    match env::var("BROWSER") {
        Ok(browser) if !browser.is_empty() => {
            if Command::new(&browser).arg(url).spawn().is_err() {
                eprintln!("Failed to open browser. App is running at {}", url);
            }
        },
        _ => println!("App is running at {}", url),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn test_wait_for_port_returns_when_port_is_open() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let start = std::time::Instant::now();
        let open = wait_for_port(port);
        // an already-open port must be detected on the first probe, before any poll delay
        assert!(open, "wait_for_port should report an open port as open");
        assert!(
            start.elapsed() < Duration::from_millis(200),
            "wait_for_port should return immediately for an open port"
        );
    }
}
