use std::env;
use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use crate::status;

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

fn find_backend_pids() -> Vec<u32> {
    let mut pids = Vec::new();

    let current_dir = env::current_dir().ok();
    let current_dir_str = current_dir.as_ref().and_then(|p| p.to_str());

    // 1. Check port 3000
    if let Some(pid) = status::get_pid_for_port(3000) {
        pids.push(pid);

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

    // 2. Scan /proc for other backend/watch processes in this workspace
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

                    if is_app || is_cargo_watch || is_cargo_run {
                        pids.push(pid);
                    }
                }
            }
        }
    }

    pids
}

pub fn stop() {
    println!("Finding running backend servers...");
    let pids = find_backend_pids();
    if pids.is_empty() {
        println!("No running backend servers found.");
        return;
    }

    println!("Stopping backend server processes (PIDs: {:?})...", pids);
    for pid in &pids {
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

    println!("Backend servers stopped.");
}
