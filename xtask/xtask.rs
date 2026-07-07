use std::env;
use std::fs;
use std::io::{self, IsTerminal};
use std::path::Path;
use std::process::{Command, ExitStatus};

mod check;
mod dev;
mod docs;
mod info;
mod make;
mod prod;
mod run;
mod sqlx;
mod xmenu;

pub(crate) struct XtaskCommand {
    pub(crate) name: &'static str,
    pub(crate) description: &'static str,
    pub(crate) run: fn(args: &[String]),
}

pub(crate) struct SubcommandInfo {
    pub(crate) name: &'static str,
    pub(crate) subcommands: &'static [&'static str],
}

pub(crate) const SUBCOMMANDS: &[SubcommandInfo] = &[
    SubcommandInfo {
        name: "dev",
        subcommands: &["run", "down", "status", "init", "admin"],
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
        name: "sqlx",
        subcommands: &["init", "reset", "prepare", "check"],
    },
    SubcommandInfo {
        name: "prod",
        subcommands: &["build", "run", "down", "inspect"],
    },
];

pub(crate) const COMMANDS: &[XtaskCommand] = &[
    XtaskCommand {
        name: "dev",
        description: "Local dev environment/servers control [run | down | status | init | admin]",
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
        name: "sqlx",
        description: "SQLx utility actions [init | reset | prepare | check]",
        run: sqlx::run,
    },
    XtaskCommand {
        name: "prod",
        description: "Production Docker actions [build | run | down | inspect]",
        run: prod::run,
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
