#!/usr/bin/env bash
set -e

echo "Pre-compiling xtask..."
cargo build --package xtask

echo "Configuring Fish environment..."

# Create config directory
mkdir -p /home/vscode/.config/fish/functions
mkdir -p /home/vscode/.config/fish/completions
mkdir -p /home/vscode/.local/share/fish

# Write config.fish
cat << 'EOF' > /home/vscode/.config/fish/config.fish
if test -f ~/.config/fish/env.fish
    source ~/.config/fish/env.fish
end

# Helpful Development Abbreviations
abbr -a cld "claude"

# Git shortcuts
abbr -a gs "git status"
abbr -a gd "git diff"
abbr -a ga "git add"
abbr -a gc "git commit"
abbr -a gca "git commit -a"
abbr -a gco "git checkout"
abbr -a gb "git branch"
abbr -a gp "git push"
abbr -a gpl "git pull"
abbr -a gl "git log --oneline -n 10"
abbr -a gcb "git-cleanup-branches"

# Cargo shortcuts
abbr -a cr "cargo run --package app --all-features"
abbr -a ct "cargo test --workspace --all-targets --all-features"
abbr -a cb "cargo build --workspace --all-targets --all-features"
abbr -a cl "cargo clippy --workspace --all-targets --all-features"
abbr -a cf "cargo -q fmt --workspace"

# Cargo Xtask shortcuts
abbr -a x "cargo -q xtask"
abbr -a xd "cargo -q xtask dev"
abbr -a xm "cargo -q xtask make"
abbr -a xma "cargo -q xtask make openapi"
abbr -a xmc "cargo -q xtask make clean"
abbr -a xmb "cargo -q xtask make backend"
abbr -a xmf "cargo -q xtask make frontend"
abbr -a xmr "cargo -q xtask make release"
abbr -a xc "cargo -q xtask check"
abbr -a xcb "cargo -q xtask check backend"
abbr -a xcf "cargo -q xtask check frontend"
abbr -a xcs "cargo -q xtask check security"
abbr -a xcd "cargo -q xtask check docs"
abbr -a xcx "cargo -q xtask check sqlx"
abbr -a xs "cargo -q xtask sqlx"
abbr -a xsp "cargo -q xtask sqlx prepare"
abbr -a xp "cargo -q xtask prod"

# Directory navigation shortcuts
abbr -a .. "cd .."
abbr -a ... "cd ../.."
abbr -a .... "cd ../../.."

# Syntax highlighting custom colors
set -g fish_color_command green --bold
set -g fish_color_keyword green --bold

# Load cargo-xtask completions
if test -f ~/.config/fish/completions/cargo-xtask.fish
    source ~/.config/fish/completions/cargo-xtask.fish
end


# Prune local branches tracking remote branches deleted on GitHub (> 1 week old)
function git-cleanup-branches
    echo "Fetching and pruning remote branches..."
    git fetch --prune
    
    set -l current_time (date +%s)
    set -l current_branch (git branch --show-current)
    
    for branch in (git branch -vv | grep ': gone]' | string replace -r '^\*?\s*' '' | awk '{print $1}')
        if test "$branch" = "$current_branch"
            echo "Skipping active branch '$branch'"
            continue
        end
        if contains -- $branch main master
            continue
        end
        
        # Get the timestamp of the last commit on this branch
        set -l commit_time (git log -1 --format=%ct $branch)
        set -l age (math "$current_time - $commit_time")
        
        # 604800 seconds = 1 week
        if test $age -gt 604800
            set -l relative_age (git log -1 --format=%cr $branch)
            echo "Deleting branch '$branch' (last commit was $relative_age)..."
            git branch -D $branch
        else
            set -l relative_age (git log -1 --format=%cr $branch)
            echo "Skipping branch '$branch' (only $relative_age)"
        end
    end
end

bind `` history-pager
EOF

# Write fish_prompt.fish
cat << 'EOF' > /home/vscode/.config/fish/functions/fish_prompt.fish
function fish_prompt
    set -l dir (string replace -r "^$HOME" '~' $PWD)
    set -l git_branch (git branch --show-current 2>/dev/null)
    
    if test -n "$git_branch"
        set -l dir_len (string length "$dir")
        set -l branch_len (string length "$git_branch")
        set -l pad_len (math $COLUMNS - $dir_len - $branch_len)
        if test $pad_len -lt 1
            set pad_len 1
        end
        set -l padding (string repeat -n $pad_len " ")
        
        set_color -o 005fff
        echo -n "$dir"
        set_color normal
        echo -n "$padding"
        set_color green
        echo "$git_branch"
        set_color normal
    else
        set_color -o 005fff
        echo "$dir"
        set_color normal
    end

    echo -n "❯ "
end
EOF

# Generate shell completions
COMPLETIONS_DIR="/home/vscode/.config/fish/completions"

if command -v rustup &> /dev/null; then
    rustup completions fish > "$COMPLETIONS_DIR/rustup.fish"
fi
# if command -v cargo &> /dev/null; then
#     rustup completions fish cargo > "$COMPLETIONS_DIR/cargo.fish"
# fi
if command -v uv &> /dev/null; then
    uv generate-shell-completion fish > "$COMPLETIONS_DIR/uv.fish"
fi

/workspaces/svelaxum/target/debug/xtask completions > "$COMPLETIONS_DIR/cargo-xtask.fish"

echo "Fish configuration complete."



# Configure Antigravity CLI Permissions (Auto-Approve safe tools)
echo "Configuring Antigravity CLI Permissions..."
mkdir -p /home/vscode/.gemini/antigravity-cli
cat << 'EOF' > /home/vscode/.gemini/antigravity-cli/settings.json
{
  "permissions": {
    "allow": [
      "read_file(/workspaces/svelaxum)",
      "write_file(/workspaces/svelaxum)",
      "command(cargo)",
      "command(cat)",
      "command(cp)",
      "command(date)",
      "command(echo)",
      "command(find)",
      "command(git diff)",
      "command(git log)",
      "command(git rev-parse)",
      "command(git show)",
      "command(git status)",
      "command(grep)",
      "command(head)",
      "command(jq)",
      "command(ls)",
      "command(mkdir)",
      "command(node)",
      "command(npm)",
      "command(npx)",
      "command(npx prettier)",
      "command(npx svelte-check)",
      "command(npx tsc)",
      "command(npx vitest)",
      "command(ps)",
      "command(rg)",
      "command(tail)",
      "command(touch)",
      "command(which)"
    ],
    "deny": [
      "command(git push)"
    ],
    "ask": [
      "command(git add)",
      "command(git branch)",
      "command(git checkout)",
      "command(git clean)",
      "command(git commit)",
      "command(git fetch)",
      "command(git merge)",
      "command(git pull)",
      "command(git reset)",
      "command(git stash)"
    ]
  }
}
EOF

# Configure Claude Code (local shims, git-ignored - the repo itself stays agent-agnostic)
echo "Configuring Claude Code..."
REPO_DIR="/workspaces/svelaxum"
# Claude Code reads CLAUDE.md; point it at the agent-agnostic AGENTS.md
echo "@AGENTS.md" > "$REPO_DIR/CLAUDE.md"
# Claude Code discovers skills under .claude/skills; reuse the shared .agents/skills
mkdir -p "$REPO_DIR/.claude"
ln -sfn ../.agents/skills "$REPO_DIR/.claude/skills"
# Install the status line script
mkdir -p /home/vscode/.claude
cp "$REPO_DIR/.devcontainer/statusline-command.sh" /home/vscode/.claude/statusline-command.sh
chmod +x /home/vscode/.claude/statusline-command.sh

# Auto-approve safe tools (mirrors the Antigravity allowlist) + status line
cat << 'EOF' > "$REPO_DIR/.claude/settings.json"
{
  "statusLine": {
    "type": "command",
    "command": "bash ~/.claude/statusline-command.sh",
    "refreshInterval": 60
  },
  "permissions": {
    "allow": [
      "Bash(ls:*)",
      "Bash(cat:*)",
      "Bash(head:*)",
      "Bash(tail:*)",
      "Bash(find:*)",
      "Bash(echo:*)",
      "Bash(rg:*)",
      "Bash(grep:*)",
      "Bash(jq:*)",
      "Bash(cargo fmt:*)",
      "Bash(cargo clippy:*)",
      "Bash(cargo check:*)",
      "Bash(cargo test:*)",
      "Bash(cargo build:*)",
      "Bash(cargo xtask check:*)",
      "Bash(cargo xtask sqlx:*)",
      "Bash(cargo xtask dev:*)",
      "Bash(cargo xtask make:*)",
      "Bash(cargo xtask prod:*)",
      "Bash(npx prettier:*)",
      "Bash(npx svelte-check:*)",
      "Bash(npx vitest run:*)",
      "Bash(npx tsc:*)"
    ],
    "deny": [
      "Bash(git push:*)"
    ]
  }
}
EOF

# Ensure local bin directory exists
mkdir -p /home/vscode/.local/bin

echo "Checking for CLI updates in the background..."
if curl -s --connect-timeout 2 google.com &>/dev/null; then
    (agy update </dev/null &>/dev/null) &
    (claude update </dev/null &>/dev/null) &
fi
