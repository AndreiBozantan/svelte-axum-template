use std::fs;
use std::net::TcpStream;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

struct CacheData {
    clippy_issues: usize,
    tests_passed: usize,
    tests_failed: usize,
    last_run_timestamp: u64,
}

fn load_cache() -> Option<CacheData> {
    let content = fs::read_to_string("target/xtask-status-cache.json").ok()?;
    let clippy_issues = extract_json_num(&content, "clippy_issues")?;
    let tests_passed = extract_json_num(&content, "tests_passed")?;
    let tests_failed = extract_json_num(&content, "tests_failed")?;
    let last_run_timestamp = extract_json_u64(&content, "last_run_timestamp")?;
    Some(CacheData {
        clippy_issues,
        tests_passed,
        tests_failed,
        last_run_timestamp,
    })
}

fn save_cache(cache: &CacheData) -> std::io::Result<()> {
    let _ = fs::create_dir_all("target");
    let content = format!(
        "{{\n  \"clippy_issues\": {},\n  \"tests_passed\": {},\n  \"tests_failed\": {},\n  \"last_run_timestamp\": {}\n}}",
        cache.clippy_issues, cache.tests_passed, cache.tests_failed, cache.last_run_timestamp
    );
    fs::write("target/xtask-status-cache.json", content)
}

fn extract_json_num(content: &str, key: &str) -> Option<usize> {
    let pattern = format!("\"{}\":", key);
    let idx = content.find(&pattern)?;
    let start = idx + pattern.len();
    let rest = &content[start..];
    let end = rest.find(|c: char| !c.is_numeric() && c != ' ').map(|i| start + i)?;
    content[start..end].trim().parse::<usize>().ok()
}

fn extract_json_u64(content: &str, key: &str) -> Option<u64> {
    let pattern = format!("\"{}\":", key);
    let idx = content.find(&pattern)?;
    let start = idx + pattern.len();
    let rest = &content[start..];
    let end = rest.find(|c: char| !c.is_numeric() && c != ' ').map(|i| start + i)?;
    content[start..end].trim().parse::<u64>().ok()
}

fn run_clippy_and_count() -> usize {
    let output = Command::new("cargo")
        .args(["clippy", "--workspace --message-format=json"])
        .output();
    
    let mut count = 0;
    if let Ok(out) = output {
        let stdout = String::from_utf8_lossy(&out.stdout);
        for line in stdout.lines() {
            if line.contains("\"reason\":\"compiler-message\"") && (line.contains("\"level\":\"warning\"") || line.contains("\"level\":\"error\"")) {
                count += 1;
            }
        }
    }
    count
}

fn run_tests_and_count() -> (usize, usize) {
    let output = Command::new("cargo")
        .args(["test"])
        .output();
    
    let mut total_passed = 0;
    let mut total_failed = 0;
    if let Ok(out) = output {
        let stdout = String::from_utf8_lossy(&out.stdout);
        for line in stdout.lines() {
            if line.contains("test result:") {
                let mut passed = 0;
                let mut failed = 0;
                if let Some(passed_idx) = line.find("passed") {
                    let start = line[..passed_idx].trim_end();
                    if let Some(space_idx) = start.rfind(' ') {
                        if let Ok(num) = start[space_idx..].trim().parse::<usize>() {
                            passed = num;
                        }
                    }
                }
                if let Some(failed_idx) = line.find("failed") {
                    let start = line[..failed_idx].trim_end();
                    if let Some(space_idx) = start.rfind(' ') {
                        if let Ok(num) = start[space_idx..].trim().parse::<usize>() {
                            failed = num;
                        }
                    }
                }
                total_passed += passed;
                total_failed += failed;
            }
        }
    }
    (total_passed, total_failed)
}

fn refresh_cache_sync() -> CacheData {
    let clippy_issues = run_clippy_and_count();
    let (tests_passed, tests_failed) = run_tests_and_count();
    let last_run_timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    CacheData {
        clippy_issues,
        tests_passed,
        tests_failed,
        last_run_timestamp,
    }
}

fn get_branch_name() -> String {
    let mut branch = String::new();
    if let Ok(output) = Command::new("git").args(["branch", "--show-current"]).output() {
        if output.status.success() {
            branch = String::from_utf8_lossy(&output.stdout).trim().to_string();
        }
    }
    if branch.is_empty() {
        if let Ok(output) = Command::new("git").args(["rev-parse", "--short", "HEAD"]).output() {
            if output.status.success() {
                branch = String::from_utf8_lossy(&output.stdout).trim().to_string();
            }
        }
    }
    if branch.is_empty() {
        branch = "unknown".to_string();
    }
    branch
}

fn get_db_info() -> String {
    let db_path = Path::new("data/db.sqlite");
    if !db_path.exists() {
        return "not found".to_string();
    }

    let size_bytes = fs::metadata(db_path).map(|m| m.len()).unwrap_or(0);
    let size_str = if size_bytes < 1024 {
        format!("{} B", size_bytes)
    } else if size_bytes < 1024 * 1024 {
        format!("{} KB", size_bytes / 1024)
    } else {
        format!("{:.1} MB", (size_bytes as f64) / (1024.0 * 1024.0))
    };

    let mut migrations_count = 0;
    let mut head_migration = "none".to_string();

    if let Ok(output) = Command::new("sqlite3")
        .args([
            "data/db.sqlite",
            "SELECT (SELECT COUNT(*) FROM _sqlx_migrations), version, description FROM _sqlx_migrations ORDER BY version DESC LIMIT 1;",
        ])
        .output()
    {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let trimmed = stdout.trim();
            if !trimmed.is_empty() {
                let parts: Vec<&str> = trimmed.split('|').collect();
                if parts.len() >= 3 {
                    if let Ok(count) = parts[0].parse::<usize>() {
                        migrations_count = count;
                    }
                    if let Ok(version) = parts[1].parse::<i64>() {
                        let description = parts[2];
                        let mut found_file = None;
                        if let Ok(entries) = fs::read_dir("migrations") {
                            for entry in entries.flatten() {
                                let filename = entry.file_name().to_string_lossy().to_string();
                                if filename.ends_with(".sql") {
                                    let v_str_2 = format!("{:02}_", version);
                                    let v_str_4 = format!("{:04}_", version);
                                    let v_str_raw = format!("{}_", version);
                                    if filename.starts_with(&v_str_2)
                                        || filename.starts_with(&v_str_4)
                                        || filename.starts_with(&v_str_raw)
                                    {
                                        found_file = Some(
                                            filename.strip_suffix(".sql").unwrap().to_string(),
                                        );
                                        break;
                                    }
                                }
                            }
                        }
                        head_migration = found_file.unwrap_or_else(|| {
                            format!("{:04}_{}", version, description.replace(' ', "_"))
                        });
                    }
                }
            }
        }
    }

    format!(
        "db.sqlite ({}, {} migrations applied, head: {})",
        size_str, migrations_count, head_migration
    )
}

fn get_pid_for_port(port: u16) -> Option<u32> {
    if let Ok(output) = Command::new("ss").args(["-tlnp"]).output() {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 6 {
                    let local_addr = parts[3];
                    if let Some(port_str) = local_addr.split(':').last() {
                        if port_str == port.to_string() {
                            let process_info = parts[5];
                            if let Some(pid_idx) = process_info.find("pid=") {
                                let start = pid_idx + 4;
                                let rest = &process_info[start..];
                                let end = rest.find(|c: char| !c.is_numeric()).map(|i| start + i).unwrap_or(process_info.len());
                                if let Ok(pid) = process_info[start..end].parse::<u32>() {
                                    return Some(pid);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if let Ok(output) = Command::new("lsof").args(["-t", &format!("-i:{}", port)]).output() {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(first_line) = stdout.lines().next() {
                if let Ok(pid) = first_line.trim().parse::<u32>() {
                    return Some(pid);
                }
            }
        }
    }

    if let Ok(output) = Command::new("fuser").arg(&format!("{}/tcp", port)).output() {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(pid_str) = stdout.trim().split_whitespace().next() {
                if let Ok(pid) = pid_str.parse::<u32>() {
                    return Some(pid);
                }
            }
        }
    }

    None
}

fn get_service_info(port: u16) -> String {
    use std::net::SocketAddr;
    let addr_str = format!("127.0.0.1:{}", port);
    let addr: Result<SocketAddr, _> = addr_str.parse();
    
    let is_running = if let Ok(a) = addr {
        TcpStream::connect_timeout(&a, Duration::from_millis(50)).is_ok()
    } else {
        false
    };

    if !is_running {
        "stopped".to_string()
    } else if let Some(pid) = get_pid_for_port(port) {
        format!("running on :{} (pid {})", port, pid)
    } else {
        format!("running on :{}", port)
    }
}

fn get_dirty_files_info() -> String {
    if let Ok(output) = Command::new("git").args(["status", "--porcelain"]).output() {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let mut modified = 0;
            let mut untracked = 0;
            for line in stdout.lines() {
                if line.trim().is_empty() {
                    continue;
                }
                if line.starts_with("??") {
                    untracked += 1;
                } else {
                    modified += 1;
                }
            }
            if modified == 0 && untracked == 0 {
                "clean".to_string()
            } else {
                match (modified, untracked) {
                    (m, 0) => format!("{} modified", m),
                    (0, u) => format!("{} untracked", u),
                    (m, u) => format!("{} modified, {} untracked", m, u),
                }
            }
        } else {
            "unknown".to_string()
        }
    } else {
        "unknown".to_string()
    }
}

fn count_dir_size(dir: &Path, exclude_dirs: &[&str], exclude_files: &[&str]) -> (usize, usize) {
    let mut file_count = 0;
    let mut line_count = 0;

    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if path.is_dir() {
                    if exclude_dirs.contains(&name) {
                        continue;
                    }
                    let (c, l) = count_dir_size(&path, exclude_dirs, exclude_files);
                    file_count += c;
                    line_count += l;
                } else if path.is_file() {
                    if exclude_files.contains(&name)
                        || name.starts_with('.')
                        || name == "package-lock.json"
                    {
                        continue;
                    }
                    if let Ok(metadata) = entry.metadata() {
                        if metadata.len() > 1_024_000 {
                            continue;
                        }
                    }
                    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                    let text_extensions = [
                        "rs", "toml", "svelte", "ts", "js", "css", "html", "json", "md", "sql", "sh",
                        "yml", "yaml",
                    ];
                    if text_extensions.contains(&ext) || ext.is_empty() {
                        if let Ok(content) = fs::read_to_string(&path) {
                            file_count += 1;
                            line_count += content.lines().count();
                        }
                    }
                }
            }
        }
    }

    (file_count, line_count)
}

fn print_row(key: &str, value: &str) {
    println!("{:<15}{}", key, value);
}

pub fn status(refresh: bool, refresh_silent: bool) {
    if refresh_silent {
        let cache = refresh_cache_sync();
        let _ = save_cache(&cache);
        return;
    }

    let cache = if refresh {
        println!("Refreshing status cache...");
        let c = refresh_cache_sync();
        let _ = save_cache(&c);
        c
    } else {
        match load_cache() {
            Some(c) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                if now.saturating_sub(c.last_run_timestamp) > 30 {
                    let _ = Command::new("cargo")
                        .args(["xtask", "status", "--refresh-silent"])
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .spawn();
                }
                c
            }
            None => {
                println!("Initializing status cache (running clippy and tests)...");
                let c = refresh_cache_sync();
                let _ = save_cache(&c);
                c
            }
        }
    };

    let branch = get_branch_name();
    print_row("Branch:", &branch);

    let db_info = get_db_info();
    print_row("DB:", &db_info);

    let backend_info = get_service_info(3000);
    print_row("Backend:", &backend_info);

    let frontend_info = get_service_info(5173);
    print_row("Frontend:", &frontend_info);

    let dirty_info = get_dirty_files_info();
    print_row("Dirty files:", &dirty_info);

    let clippy_info = if cache.clippy_issues == 0 {
        "clean".to_string()
    } else {
        format!("{} issues", cache.clippy_issues)
    };
    print_row("Clippy:", &clippy_info);

    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .saturating_sub(cache.last_run_timestamp);
    let elapsed_str = if elapsed < 60 {
        "just now".to_string()
    } else if elapsed < 3600 {
        format!("{} min ago", elapsed / 60)
    } else {
        format!("{} hours ago", elapsed / 3600)
    };
    let tests_info = format!(
        "{} passing, {} failing (last run: {})",
        cache.tests_passed, cache.tests_failed, elapsed_str
    );
    print_row("Tests:", &tests_info);

    let (fe_files, fe_lines) = count_dir_size(
        Path::new("frontend"),
        &["node_modules", "dist", ".svelte-kit", ".git"],
        &["package-lock.json", ".DS_Store"],
    );
    let fe_size_info = format!("{} files; {} lines of code", fe_files, fe_lines);
    print_row("Frontend size:", &fe_size_info);

    let (be_files, be_lines) = count_dir_size(
        Path::new("backend"),
        &["target", ".sqlx", ".git"],
        &[".DS_Store"],
    );
    let be_size_info = format!("{} files; {} lines of code", be_files, be_lines);
    print_row("Backend size:", &be_size_info);

    let toolchain_info = get_toolchain_info();
    print_row("Toolchain:", &toolchain_info);
}

fn get_toolchain_info() -> String {
    let rustc_ver = get_tool_version("rustc", &["--version"]);
    let rustc_short = rustc_ver.split_whitespace().nth(1).unwrap_or("unknown");
    
    let cargo_ver = get_tool_version("cargo", &["--version"]);
    let cargo_short = cargo_ver.split_whitespace().nth(1).unwrap_or("unknown");
    
    let node_ver = get_tool_version("node", &["--version"]);
    let npm_ver = get_tool_version("npm", &["--version"]);
    
    format!(
        "rustc {}; cargo {}; node {}; npm {}",
        rustc_short, cargo_short, node_ver, npm_ver
    )
}

fn get_tool_version(cmd: &str, args: &[&str]) -> String {
    if let Ok(output) = Command::new(cmd).args(args).output() {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let val = stdout.trim();
            if !val.is_empty() {
                return val.to_string();
            }
        }
    }
    "unknown".to_string()
}
