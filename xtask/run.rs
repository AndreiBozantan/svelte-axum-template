use crate::run_command;
use crate::sqlx;
use std::net::TcpStream;
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::Duration;

pub fn run() {
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
