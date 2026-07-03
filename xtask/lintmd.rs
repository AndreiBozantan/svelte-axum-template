use std::collections::HashMap;
use std::collections::HashSet;
use std::fs;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

/// Validates all relative markdown links (including `#heading` anchors) across the
/// repo's tracked markdown files. External `http(s)`/`mailto` links are ignored.
/// Anchors follow the GitHub algorithm: lowercase, punctuation stripped, spaces to
/// hyphens, `-N` suffix for duplicates.
pub fn check_md_links() -> std::io::Result<()> {
    println!("Checking markdown links...");
    let md_files = git_ls_md_files()?;

    let mut anchor_cache: HashMap<PathBuf, HashSet<String>> = HashMap::new();
    let mut errors = Vec::new();

    for file in &md_files {
        let Ok(text) = fs::read_to_string(file) else {
            continue;
        };
        let dir = file.parent().unwrap_or(Path::new("."));
        for (target, anchor) in extract_links(&text) {
            let resolved = if target.is_empty() {
                file.clone()
            } else {
                normalize(&dir.join(&target))
            };
            if !resolved.is_file() {
                errors.push(format!("{}: broken link -> {}", file.display(), target));
            } else if !anchor.is_empty() {
                let anchors = anchor_cache
                    .entry(resolved.clone())
                    .or_insert_with(|| heading_anchors(&resolved));
                if !anchors.contains(&anchor) {
                    errors.push(format!("{}: missing anchor -> {}#{}", file.display(), target, anchor));
                }
            }
        }
    }

    for error in &errors {
        eprintln!("{error}");
    }
    if errors.is_empty() {
        println!("All markdown links ok ({} files checked).", md_files.len());
        Ok(())
    } else {
        eprintln!("{} broken markdown link(s) found.", errors.len());
        std::process::exit(1);
    }
}

/// Lists tracked markdown files via `git ls-files`, which honors `.gitignore` and
/// skips untracked/ignored paths (build output, vendored deps, local agent shims).
fn git_ls_md_files() -> std::io::Result<Vec<PathBuf>> {
    let output = Command::new("git").args(["ls-files", "-z", "*.md"]).output()?;
    if !output.status.success() {
        return Err(std::io::Error::other("failed to run git ls-files"));
    }
    Ok(output
        .stdout
        .split(|&b| b == 0)
        .filter(|entry| !entry.is_empty())
        .map(|entry| PathBuf::from(String::from_utf8_lossy(entry).into_owned()))
        .collect())
}

/// True for a line that opens or closes a fenced code block (```` ``` ```` or `~~~`).
fn is_fence_delimiter(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("```") || trimmed.starts_with("~~~")
}

/// Extracts `(target, anchor)` pairs from `[text](target.md#anchor)` links.
/// Either part may be empty (`(#anchor)` is a same-file link); non-`.md` targets are skipped.
fn extract_links(text: &str) -> Vec<(String, String)> {
    let mut links = Vec::new();
    let mut in_fence = false;
    for line in text.lines() {
        if is_fence_delimiter(line) {
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            continue;
        }
        let mut rest = line;
        while let Some(pos) = rest.find("](") {
            rest = &rest[pos + 2..];
            let Some(end) = rest.find(')') else {
                break;
            };
            let candidate = &rest[..end];
            rest = &rest[end + 1..];
            if candidate.starts_with("http://")
                || candidate.starts_with("https://")
                || candidate.starts_with("mailto:")
                || candidate.contains(char::is_whitespace)
            {
                continue;
            }
            let (target, anchor) = candidate.split_once('#').unwrap_or((candidate, ""));
            if (target.is_empty() && anchor.is_empty()) || (!target.is_empty() && !target.ends_with(".md")) {
                continue;
            }
            links.push((target.to_string(), anchor.to_string()));
        }
    }
    links
}

/// Collects the GitHub-style anchors of all `#`-headings in a markdown file.
fn heading_anchors(path: &Path) -> HashSet<String> {
    let mut anchors = HashSet::new();
    let Ok(text) = fs::read_to_string(path) else {
        return anchors;
    };
    let mut seen: HashMap<String, usize> = HashMap::new();
    let mut in_fence = false;
    for line in text.lines() {
        if is_fence_delimiter(line) {
            in_fence = !in_fence;
            continue;
        }
        if in_fence || !line.starts_with('#') {
            continue;
        }
        let heading = line.trim_start_matches('#');
        if !heading.starts_with(' ') {
            continue;
        }
        let anchor = github_anchor(strip_closing_hashes(heading.trim()));
        let count = seen.entry(anchor.clone()).or_insert(0);
        anchors.insert(if *count == 0 {
            anchor.clone()
        } else {
            format!("{anchor}-{count}")
        });
        *count += 1;
    }
    anchors
}

/// Drops an optional closing ATX sequence (`## Title ##` -> `Title`), which GitHub
/// ignores when generating the anchor. A trailing run of `#`s only closes the heading
/// when preceded by whitespace, so content like `C#` is left intact.
fn strip_closing_hashes(heading: &str) -> &str {
    match heading.rsplit_once(char::is_whitespace) {
        Some((head, tail)) if !tail.is_empty() && tail.bytes().all(|b| b == b'#') => head.trim_end(),
        _ => heading,
    }
}

fn github_anchor(heading: &str) -> String {
    heading
        .to_lowercase()
        .chars()
        .filter_map(|c| match c {
            ' ' => Some('-'),
            '-' | '_' => Some(c),
            c if c.is_alphanumeric() => Some(c),
            _ => None,
        })
        .collect()
}

/// Resolves `.` and `..` components without touching the filesystem.
fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                out.pop();
            },
            Component::CurDir => {},
            other => out.push(other),
        }
    }
    out
}
