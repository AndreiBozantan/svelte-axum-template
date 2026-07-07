use std::process::Command;

fn is_docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

pub fn handle_docker_command(subcommand: Option<&str>) -> std::io::Result<()> {
    let commands = [
        (
            "build",
            "Builds the production Docker image via docker compose",
            "docker compose build",
        ),
        (
            "run",
            "Runs the production Docker container locally",
            "docker compose up -d",
        ),
        (
            "down",
            "Stops and removes the production Docker container",
            "docker compose down",
        ),
        (
            "debug",
            "Runs a debug container mounting the data volume",
            "docker run --rm -it --mount type=volume,src=svelaxum-data,dst=/data debian:bookworm-slim bash",
        ),
    ];

    let subcommand = match subcommand {
        None => {
            println!("Docker Commands Cheat Sheet (for host machine or devcontainer):");
            println!();
            for (name, desc, cmd) in &commands {
                println!("  cargo xtask docker {:<6} - {}", name, desc);
                println!("    {}", cmd);
                println!();
            }
            return Ok(());
        },
        Some(s) => s,
    };

    let matched = commands.iter().find(|(name, _, _)| *name == subcommand);
    if matched.is_none() {
        eprintln!("Unknown docker subcommand: {}", subcommand);
        println!();
        println!("Available subcommands:");
        for (name, desc, _) in &commands {
            println!("  {:<6} - {}", name, desc);
        }
        std::process::exit(1);
    }
    let (_, _, cmd_str) = matched.unwrap();

    let parts: Vec<&str> = cmd_str.split_whitespace().collect();
    let exe = parts[0];
    let args = &parts[1..];

    if !is_docker_available() {
        println!("[!] Docker daemon is not accessible in this container.");
        println!("[i] Please run this command on your host machine:");
        println!();
        println!("{}", cmd_str);
        println!();
    } else {
        println!("Executing: {}", cmd_str);
        let mut child = Command::new(exe).args(args).spawn()?;
        let status = child.wait()?;
        if !status.success() {
            std::process::exit(status.code().unwrap_or(1));
        }
    }
    Ok(())
}

pub fn run(args: &[String]) {
    let subcommand = args.get(2).map(String::as_str);
    if let Err(e) = handle_docker_command(subcommand) {
        eprintln!("Docker command failed: {}", e);
        std::process::exit(1);
    }
}
