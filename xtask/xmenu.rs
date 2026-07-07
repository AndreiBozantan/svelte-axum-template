use std::io::{self, Read, Write};
use std::process::Command;

use crate::{COMMANDS, SUBCOMMANDS, SubcommandInfo, XtaskCommand};

pub(crate) fn run_interactive_menu() {
    let mut main_selected = 0;
    let visible_commands: Vec<&XtaskCommand> = COMMANDS
        .iter()
        .filter(|c| {
            c.name != "pre-commit" && c.name != "pre-push" && c.name != "setup-hooks" && c.name != "completions"
        })
        .collect();

    let mut guard = RawModeGuard::enable();

    loop {
        // Clear screen, move cursor to top-left, hide cursor
        print!("\x1B[H\x1B[2J\x1B[?25l");
        println!("=== Svelaxum Xtask Interactive Menu ===\r");
        println!("Use Up/Down Arrow keys to navigate, Enter to select, 'q' or Esc to exit.\r\n\r");

        if main_selected == 0 {
            println!(" > \x1B[1;33m[Esc] [ Quit ]\x1B[0m\r");
        } else {
            println!("   [Esc] [ Quit ]\r");
        }

        for (i, cmd) in visible_commands.iter().enumerate() {
            let idx = i + 1;
            let shortcut = cmd.name.chars().next().unwrap().to_ascii_lowercase();
            if idx == main_selected {
                println!(
                    " > \x1B[1;36m[{}] {:<8}\x1B[0m - {}\r",
                    shortcut, cmd.name, cmd.description
                );
            } else {
                println!("   [{}] {:<8} - {}\r", shortcut, cmd.name, cmd.description);
            }
        }

        let _ = io::stdout().flush();

        match read_key() {
            Key::Up => {
                if main_selected > 0 {
                    main_selected -= 1;
                } else {
                    main_selected = visible_commands.len();
                }
            },
            Key::Down => {
                if main_selected < visible_commands.len() {
                    main_selected += 1;
                } else {
                    main_selected = 0;
                }
            },
            Key::Enter => {
                if main_selected == 0 {
                    break;
                }

                let selected_cmd = visible_commands[main_selected - 1];

                if let Some(sub_info) = SUBCOMMANDS.iter().find(|s| s.name == selected_cmd.name) {
                    match run_sub_menu(selected_cmd, sub_info, guard) {
                        Ok(g) => {
                            guard = g; // Returned back, keep running main menu
                        },
                        Err(()) => {
                            break; // Executed command, exit main menu
                        },
                    }
                } else {
                    execute_command(selected_cmd.name, None, guard);
                    break;
                }
            },
            Key::Char(c) => {
                if c == 'q' {
                    break;
                }
                if let Some(pos) = visible_commands
                    .iter()
                    .position(|cmd| cmd.name.chars().next().unwrap().to_ascii_lowercase() == c)
                {
                    main_selected = pos + 1;
                }
            },
            Key::Escape | Key::CtrlC => {
                break;
            },
            _ => {},
        }
    }
}

fn assign_shortcuts(options: &[String]) -> Vec<char> {
    let mut reserved = std::collections::HashSet::new();
    reserved.insert('q');

    let mut shortcuts = Vec::new();
    // The first option is always '[ Back ]', which gets '\x1b' (Escape)
    shortcuts.push('\x1b');

    for opt in options.iter().skip(1) {
        // clean up option name for finding characters
        // e.g. "dev (default)" -> check "dev"
        let clean_name = if let Some(idx) = opt.find(" (default)") {
            &opt[..idx]
        } else {
            opt.as_str()
        };

        let mut found = false;
        for c in clean_name.chars() {
            let lower = c.to_ascii_lowercase();
            if lower.is_ascii_alphabetic() && !reserved.contains(&lower) {
                reserved.insert(lower);
                shortcuts.push(lower);
                found = true;
                break;
            }
        }

        if !found {
            // Find any unused lowercase letter
            for c in b'a'..=b'z' {
                let letter = c as char;
                if !reserved.contains(&letter) {
                    reserved.insert(letter);
                    shortcuts.push(letter);
                    found = true;
                    break;
                }
            }
        }

        if !found {
            // Fallback
            shortcuts.push(' ');
        }
    }
    shortcuts
}

fn run_sub_menu(
    cmd: &XtaskCommand,
    sub_info: &SubcommandInfo,
    guard: RawModeGuard,
) -> Result<RawModeGuard, ()> {
    let mut selected = 0;

    let mut options = vec!["[ Back ]".to_string(), format!("{} (default)", cmd.name)];
    for sub in sub_info.subcommands {
        options.push(sub.name.to_string());
    }

    let shortcuts = assign_shortcuts(&options);

    loop {
        print!("\x1B[H\x1B[2J\x1B[?25l");
        println!("=== Svelaxum Xtask > {} ===\r", cmd.name);
        println!("Use Up/Down Arrow keys to navigate, Enter to select, 'q'/Esc/Back to return.\r\n\r");

        for (i, opt) in options.iter().enumerate() {
            let prefix = if i == selected { " > " } else { "   " };
            if i == 0 {
                if i == selected {
                    println!("{}\x1B[1;33m[Esc] {}\x1B[0m\r", prefix, opt);
                } else {
                    println!("{}[Esc] {}\r", prefix, opt);
                }
            } else {
                let desc = if i == 1 {
                    sub_info.default_description
                } else {
                    sub_info.subcommands[i - 2].description
                };

                if i == selected {
                    println!("{}\x1B[1;36m[{}] {:<16}\x1B[0m - {}\r", prefix, shortcuts[i], opt, desc);
                } else {
                    println!("{}[{}] {:<16} - {}\r", prefix, shortcuts[i], opt, desc);
                }
            }
        }

        let _ = io::stdout().flush();

        match read_key() {
            Key::Up => {
                if selected > 0 {
                    selected -= 1;
                } else {
                    selected = options.len() - 1;
                }
            },
            Key::Down => {
                if selected < options.len() - 1 {
                    selected += 1;
                } else {
                    selected = 0;
                }
            },
            Key::Enter => {
                if selected == 0 {
                    return Ok(guard);
                } else if selected == 1 {
                    execute_command(cmd.name, None, guard);
                    return Err(());
                } else {
                    let sub = &options[selected];
                    execute_command(cmd.name, Some(sub), guard);
                    return Err(());
                }
            },
            Key::Char(c) => {
                if c == 'q' {
                    return Ok(guard);
                }
                if let Some(pos) = shortcuts.iter().position(|&s| s == c) {
                    selected = pos;
                }
            },
            Key::Escape => {
                return Ok(guard);
            },
            Key::CtrlC => {
                drop(guard);
                std::process::exit(0);
            },
            _ => {},
        }
    }
}

fn execute_command(
    cmd_name: &str,
    subcommand: Option<&str>,
    guard: RawModeGuard,
) {
    drop(guard);

    // Clear screen and show cursor
    print!("\x1B[H\x1B[2J\x1B[?25h");
    let _ = io::stdout().flush();

    let mut args = vec!["cargo".to_string(), cmd_name.to_string()];
    if let Some(sub) = subcommand {
        args.push(sub.to_string());
        println!("Executing: cargo xtask {} {}\n", cmd_name, sub);
    } else {
        println!("Executing: cargo xtask {}\n", cmd_name);
    }

    if let Some(cmd) = COMMANDS.iter().find(|c| c.name == cmd_name) {
        (cmd.run)(&args);
    } else {
        eprintln!("Unknown command: {}", cmd_name);
        std::process::exit(1);
    }
}

struct RawModeGuard;

impl RawModeGuard {
    fn enable() -> Self {
        let _ = Command::new("stty").args(["raw", "-echo"]).status();
        RawModeGuard
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = Command::new("stty").args(["-raw", "echo"]).status();
        print!("\x1B[?25h"); // Ensure cursor is shown
        let _ = io::stdout().flush();
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Key {
    Up,
    Down,
    Enter,
    Escape,
    CtrlC,
    Char(char),
    Unknown,
}

fn read_key() -> Key {
    let mut stdin = io::stdin();
    let mut buf = [0; 3];
    let n = match stdin.read(&mut buf) {
        Ok(n) => n,
        Err(_) => return Key::Unknown,
    };
    parse_key_from_bytes(&buf[..n])
}

fn parse_key_from_bytes(bytes: &[u8]) -> Key {
    if bytes.is_empty() {
        return Key::Unknown;
    }
    match bytes[0] {
        3 => Key::CtrlC,
        13 | 10 => Key::Enter,
        27 => {
            if bytes.len() >= 3 && bytes[1] == 91 {
                match bytes[2] {
                    65 => Key::Up,
                    66 => Key::Down,
                    _ => Key::Unknown,
                }
            } else if bytes.len() == 1 {
                Key::Escape
            } else {
                Key::Unknown
            }
        },
        b => {
            let c = b as char;
            if c.is_ascii_alphabetic() {
                Key::Char(c.to_ascii_lowercase())
            } else {
                Key::Unknown
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_key() {
        assert_eq!(parse_key_from_bytes(&[3]), Key::CtrlC);
        assert_eq!(parse_key_from_bytes(&[13]), Key::Enter);
        assert_eq!(parse_key_from_bytes(&[27, 91, 65]), Key::Up);
        assert_eq!(parse_key_from_bytes(&[27, 91, 66]), Key::Down);
        assert_eq!(parse_key_from_bytes(b"q"), Key::Char('q'));
        assert_eq!(parse_key_from_bytes(&[27]), Key::Escape);
    }

    #[test]
    fn test_assign_shortcuts() {
        let options = vec![
            "[ Back ]".to_string(),
            "dev (default)".to_string(),
            "run".to_string(),
            "down".to_string(),
            "status".to_string(),
            "init".to_string(),
            "admin".to_string(),
        ];
        let shortcuts = assign_shortcuts(&options);
        assert_eq!(shortcuts, vec!['\x1b', 'd', 'r', 'o', 's', 'i', 'a']);
    }
}
