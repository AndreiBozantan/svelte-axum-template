use std::process::ExitStatus;

pub fn docker_build() -> std::io::Result<ExitStatus> {
    println!("Building production docker image via docker compose...");
    crate::run_command("docker", &["compose", "build"], None)
}

pub fn docker_run() -> std::io::Result<ExitStatus> {
    println!("Running release container via docker compose...");
    crate::run_command("docker", &["compose", "up", "-d"], None)
}

pub fn docker_down() -> std::io::Result<ExitStatus> {
    println!("Stopping and removing release container via docker compose...");
    crate::run_command("docker", &["compose", "down"], None)
}

pub fn docker_debug() -> std::io::Result<ExitStatus> {
    println!("Starting debug container with data volume mounted...");
    crate::run_command(
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
