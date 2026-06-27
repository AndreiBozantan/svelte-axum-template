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
abbr -a gs "git status"
abbr -a gd "git diff"
abbr -a ga "git add"
abbr -a gca "git commit -a"
abbr -a gp "git push"
abbr -a gl "git log --oneline -n 10"
abbr -a gcb "git-cleanup-branches"

abbr -a cr "cargo run --package app --all-features"
abbr -a ct "cargo test --workspace --all-targets --all-features"
abbr -a cb "cargo build --workspace --all-targets --all-features"
abbr -a cc "cargo -q xtask ci-backend && cargo -q xtask ci-frontend"
abbr -a ccb "cargo -q xtask ci-backend"
abbr -a ccf "cargo -q xtask ci-frontend"
abbr -a cf "cargo -q fmt --workspace"
abbr -a cx "cargo -q xtask"
abbr -a cxd "cargo -q xtask dev"
abbr -a cxs "cargo -q xtask status"
abbr -a cxdbpr "cargo -q xtask db-prepare"
abbr -a cxapi "cargo -q xtask openapi"

# Directory navigation shortcuts
abbr -a .. "cd .."
abbr -a ... "cd ../.."
abbr -a .... "cd ../../.."

# Syntax highlighting custom colors
set -g fish_color_command green --bold
set -g fish_color_keyword green --bold

# Cargo xtask completions
complete -c cargo -n "__fish_seen_subcommand_from xtask" -f
complete -c cargo -n "__fish_seen_subcommand_from xtask" -a "(/workspaces/svelaxum/target/debug/xtask help | string match -r '^\s{2,}[a-z0-9-]+' | string trim)"


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
      "command(git status)",
      "command(git diff)",
      "command(git log)",
      "command(git show)",
      "command(git rev-parse)",
      "command(cargo)",
      "command(npm)",
      "command(npx)",
      "command(node)",
      "command(which)",
      "command(ls)",
      "command(grep)",
      "command(rg)",
      "command(cat)",
      "command(head)",
      "command(tail)",
      "command(find)",
      "command(mkdir)",
      "command(cp)",
      "command(touch)",
      "command(jq)",
      "command(ps)",
      "command(date)"
    ],
    "deny": [
      "command(git push)"
    ],
    "ask": [
      "command(git checkout)",
      "command(git add)",
      "command(git commit)",
      "command(git branch)",
      "command(git stash)",
      "command(git pull)",
      "command(git fetch)",
      "command(git merge)",
      "command(git reset)",
      "command(git clean)"
    ]
  }
}
EOF

