use std::env;
use std::fs;
use std::path::Path;
use std::process::{Command, ExitStatus};

mod check;
mod database;
mod dev;
mod docker;
mod docs;
mod info;
mod make;
mod run;

struct XtaskCommand {
    name: &'static str,
    description: &'static str,
    run: fn(args: &[String]),
}

struct SubcommandInfo {
    name: &'static str,
    subcommands: &'static [&'static str],
}

const SUBCOMMANDS: &[SubcommandInfo] = &[
    SubcommandInfo {
        name: "dev",
        subcommands: &["run", "stop", "info", "init", "create-admin"],
    },
    SubcommandInfo {
        name: "make",
        subcommands: &["all", "backend", "frontend", "release", "clean", "openapi"],
    },
    SubcommandInfo {
        name: "check",
        subcommands: &["all", "backend", "frontend", "security", "docs", "sqlx"],
    },
    SubcommandInfo {
        name: "db",
        subcommands: &["init", "reset", "prepare", "prepare-check"],
    },
    SubcommandInfo {
        name: "docker",
        subcommands: &["build", "run", "down", "debug"],
    },
];

const COMMANDS: &[XtaskCommand] = &[
    XtaskCommand {
        name: "dev",
        description: "Local dev environment/servers control [run | stop | info | init | create-admin]",
        run: dev::run,
    },
    XtaskCommand {
        name: "make",
        description: "Builds backend and frontend targets [all | backend | frontend | release | clean | openapi]",
        run: make::run,
    },
    XtaskCommand {
        name: "check",
        description: "Runs CI verification checks [backend | frontend | security | docs | sqlx]",
        run: check::run,
    },
    XtaskCommand {
        name: "db",
        description: "Database utility actions [init | reset | prepare | prepare-check]",
        run: database::run,
    },
    XtaskCommand {
        name: "docker",
        description: "Production Docker actions [build | run | down | debug]",
        run: docker::run,
    },
    XtaskCommand {
        name: "pre-commit",
        description: "Runs pre-commit checks (formatting, clippy, sqlx, svelte-check, prettier)",
        run: |_| {
            check::pre_commit().expect("failed to run pre-commit checks");
        },
    },
    XtaskCommand {
        name: "pre-push",
        description: "Runs pre-push checks (backend/frontend tests)",
        run: |_| {
            check::pre_push().expect("failed to run pre-push checks");
        },
    },
    XtaskCommand {
        name: "setup-hooks",
        description: "Sets up workspace git hooks",
        run: |_| {
            check::setup_hooks().expect("failed to set up git hooks");
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

    if task_name == "completions" {
        print!("{}", generate_completions());
        return;
    }

    // Auto-update completions in the background when running any xtask command
    ensure_fish_completions();

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
    let visible_commands: Vec<&XtaskCommand> = COMMANDS
        .iter()
        .filter(|c| c.name != "pre-commit" && c.name != "pre-push" && c.name != "setup-hooks")
        .collect();
    let max_len = visible_commands.iter().map(|c| c.name.len()).max().unwrap_or(0);
    for cmd in visible_commands {
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

fn generate_completions() -> String {
    let mut completions = String::new();
    completions.push_str("# Auto-generated cargo xtask completions\n");
    completions.push_str("complete -c cargo -n \"__fish_seen_subcommand_from xtask\" -f\n");

    let mut top_level = Vec::new();
    for cmd in COMMANDS {
        if cmd.name != "pre-commit" && cmd.name != "pre-push" && cmd.name != "setup-hooks" && cmd.name != "completions"
        {
            top_level.push(cmd.name);
        }
    }

    completions.push_str(&format!(
        "complete -c cargo -n \"__fish_seen_subcommand_from xtask; and not __fish_seen_subcommand_from {}\" -a \"{}\"\n",
        SUBCOMMANDS.iter().map(|s| s.name).collect::<Vec<_>>().join(" "),
        top_level.join(" ")
    ));

    for sub in SUBCOMMANDS {
        completions.push_str(&format!(
            "complete -c cargo -n \"__fish_seen_subcommand_from xtask; and __fish_seen_subcommand_from {}; and not __fish_seen_subcommand_from {}\" -a \"{}\"\n",
            sub.name,
            sub.subcommands.join(" "),
            sub.subcommands.join(" ")
        ));
    }

    completions
}

fn ensure_fish_completions() {
    let path = Path::new("/home/vscode/.config/fish/completions/cargo-xtask.fish");
    let Some(parent) = path.parent() else {
        return;
    };
    if !parent.exists() {
        return;
    }
    let completions = generate_completions();
    if fs::read_to_string(path).is_ok_and(|existing| existing == completions) {
        return;
    }
    let _ = fs::write(path, completions);
}
