use std::env;
use std::fs;
use std::io::{self, IsTerminal};
use std::path::Path;
use std::process::{Command, ExitStatus};

mod check;
mod dev;
mod docs;
mod make;
mod prod;
mod sqlx;
mod status;
mod xmenu;

pub(crate) struct XtaskCommand {
    pub(crate) name: &'static str,
    pub(crate) description: &'static str,
    pub(crate) run: fn(args: &[String]),
}

pub(crate) struct SubcommandDetail {
    pub(crate) name: &'static str,
    pub(crate) description: &'static str,
}

pub(crate) struct SubcommandInfo {
    pub(crate) name: &'static str,
    pub(crate) default_description: &'static str,
    pub(crate) subcommands: &'static [SubcommandDetail],
}

pub(crate) const SUBCOMMANDS: &[SubcommandInfo] = &[
    SubcommandInfo {
        name: "dev",
        default_description: "Runs dev environment if stopped, otherwise brings it down",
        subcommands: &[
            SubcommandDetail {
                name: "run",
                description: "Runs backend watch and frontend dev server",
            },
            SubcommandDetail {
                name: "down",
                description: "Stops any running backend or frontend servers",
            },
            SubcommandDetail {
                name: "status",
                description: "Displays project development status",
            },
            SubcommandDetail {
                name: "init",
                description: "Installs frontend packages, initializes DB, and seeds admin",
            },
            SubcommandDetail {
                name: "admin",
                description: "Creates/updates the admin user interactively",
            },
        ],
    },
    SubcommandInfo {
        name: "make",
        default_description: "Builds frontend and backend in debug mode",
        subcommands: &[
            SubcommandDetail {
                name: "all",
                description: "Builds frontend and backend in debug mode",
            },
            SubcommandDetail {
                name: "backend",
                description: "Builds backend in debug mode",
            },
            SubcommandDetail {
                name: "frontend",
                description: "Builds frontend",
            },
            SubcommandDetail {
                name: "release",
                description: "Builds frontend and backend in release mode",
            },
            SubcommandDetail {
                name: "clean",
                description: "Deletes build files, target, .sqlx, and node_modules",
            },
            SubcommandDetail {
                name: "openapi",
                description: "Generates OpenAPI spec and frontend client",
            },
            SubcommandDetail {
                name: "format",
                description: "Auto-formats backend (cargo fmt) and frontend (prettier)",
            },
        ],
    },
    SubcommandInfo {
        name: "check",
        default_description: "Runs all CI checks",
        subcommands: &[
            SubcommandDetail {
                name: "all",
                description: "Runs all CI checks",
            },
            SubcommandDetail {
                name: "backend",
                description: "Runs all backend CI checks (fmt, clippy, tests, drift)",
            },
            SubcommandDetail {
                name: "frontend",
                description: "Runs all frontend CI checks (prettier, typecheck, tests, build)",
            },
            SubcommandDetail {
                name: "security",
                description: "Runs semgrep security scan",
            },
            SubcommandDetail {
                name: "docs",
                description: "Validates markdown relative links and heading anchors",
            },
            SubcommandDetail {
                name: "sqlx",
                description: "Checks if SQLx offline metadata is up to date (alias)",
            },
        ],
    },
    SubcommandInfo {
        name: "sqlx",
        default_description: "Installs sqlx-cli if missing, creates DB, runs migrations, and prepares queries",
        subcommands: &[
            SubcommandDetail {
                name: "init",
                description: "Installs sqlx-cli, creates DB, runs migrations, and prepares queries",
            },
            SubcommandDetail {
                name: "reset",
                description: "Drops database and re-initializes it",
            },
            SubcommandDetail {
                name: "prepare",
                description: "Prepares SQLx offline metadata (.sqlx/)",
            },
            SubcommandDetail {
                name: "check",
                description: "Checks if SQLx offline metadata (.sqlx/) is up to date",
            },
        ],
    },
    SubcommandInfo {
        name: "prod",
        default_description: "Shows prod commands cheat sheet",
        subcommands: &[
            SubcommandDetail {
                name: "build",
                description: "Builds the production Docker image via docker compose",
            },
            SubcommandDetail {
                name: "run",
                description: "Runs the production Docker container locally",
            },
            SubcommandDetail {
                name: "down",
                description: "Stops and removes the production Docker container",
            },
            SubcommandDetail {
                name: "inspect",
                description: "Runs a debug/inspect container mounting the data volume",
            },
        ],
    },
];

pub(crate) const COMMANDS: &[XtaskCommand] = &[
    XtaskCommand {
        name: "dev",
        description: "local dev environment/servers control",
        run: dev::run,
    },
    XtaskCommand {
        name: "make",
        description: "builds/formats backend and frontend targets",
        run: make::run,
    },
    XtaskCommand {
        name: "check",
        description: "runs CI verification checks",
        run: check::run,
    },
    XtaskCommand {
        name: "sqlx",
        description: "sqlx utility actions",
        run: sqlx::run,
    },
    XtaskCommand {
        name: "prod",
        description: "production docker actions",
        run: prod::run,
    },
    XtaskCommand {
        name: "pre-commit",
        description: "runs pre-commit checks",
        run: |_| {
            check::pre_commit().expect("failed to run pre-commit checks");
        },
    },
    XtaskCommand {
        name: "pre-push",
        description: "runs pre-push checks",
        run: |_| {
            check::pre_push().expect("failed to run pre-push checks");
        },
    },
    XtaskCommand {
        name: "setup-hooks",
        description: "sets up workspace git hooks",
        run: |_| {
            check::setup_hooks().expect("failed to set up git hooks");
        },
    },
];

fn main() {
    let args: Vec<String> = env::args().collect();
    let task_name = args.get(1).map(String::as_str);

    if task_name.is_none() && io::stdin().is_terminal() && io::stdout().is_terminal() {
        ensure_fish_completions();
        xmenu::run_interactive_menu();
        return;
    }

    let task_name = task_name.unwrap_or("help");

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
        if let Some(sub_info) = SUBCOMMANDS.iter().find(|s| s.name == cmd.name) {
            let max_sub_len = sub_info.subcommands.iter().map(|s| s.name.len()).max().unwrap_or(0);
            for sub in sub_info.subcommands {
                println!("    {:width$} - {}", sub.name, sub.description, width = max_sub_len);
            }
        }
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
        let sub_names: Vec<&str> = sub.subcommands.iter().map(|s| s.name).collect();
        let sub_names_str = sub_names.join(" ");
        completions.push_str(&format!(
            "complete -c cargo -n \"__fish_seen_subcommand_from xtask; and __fish_seen_subcommand_from {}; and not __fish_seen_subcommand_from {}\" -a \"{}\"\n",
            sub.name,
            sub_names_str,
            sub_names_str
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
