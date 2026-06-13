#!/usr/bin/env bash
set -e

echo "Configuring Fish environment..."

# Create config directory
mkdir -p /home/vscode/.config/fish/functions
mkdir -p /home/vscode/.config/fish/completions
mkdir -p /home/vscode/.local/share/fish

# Write config.fish
cat << 'EOF' > /home/vscode/.config/fish/config.fish
# Helpful Development Abbreviations
abbr -a gs "git status"
abbr -a gd "git diff"
abbr -a ga "git add"
abbr -a gca "git commit -a"
abbr -a gp "git push"
abbr -a gl "git log --oneline -n 10"

abbr -a cb "cargo build"
abbr -a cr "cargo run"
abbr -a ct "cargo test"
abbr -a cc "cargo check --all-targets && cargo clippy --all-targets"          
abbr -a cf "cargo fmt"
abbr -a cx "cargo xtask"
abbr -a cxd "cargo xtask dev"

# Directory navigation shortcuts
abbr -a .. "cd .."
abbr -a ... "cd ../.."
abbr -a .... "cd ../../.."

# Syntax highlighting custom colors
set -g fish_color_command green --bold
set -g fish_color_keyword green --bold

# Cargo xtask completions
complete -c cargo -n "__fish_seen_subcommand_from xtask" -f
complete -c cargo -n "__fish_seen_subcommand_from xtask" -a "clean release lint-security db-init db-create db-migrate db-prepare db-drop db-reset dev-init dev docker-build docker-run docker-debug help"

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

# Configure Antigravity CLI Hooks
echo "Configuring Antigravity CLI Hooks..."
mkdir -p /home/vscode/.gemini/config
mkdir -p /home/vscode/.gemini/antigravity-cli
cat << 'EOF' > /home/vscode/.gemini/config/hooks.json
{
  "rust-post-edit-validation": {
    "enabled": true,
    "PostToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "/workspaces/svelaxum/.agents/post_tool_hook.sh",
            "timeout": 120
          }
        ]
      }
    ]
  }
}
EOF
if [ ! -e /home/vscode/.gemini/antigravity-cli/hooks.json ] || [ "$(realpath /home/vscode/.gemini/config/hooks.json)" != "$(realpath /home/vscode/.gemini/antigravity-cli/hooks.json)" ]; then
  cp /home/vscode/.gemini/config/hooks.json /home/vscode/.gemini/antigravity-cli/hooks.json
fi
chmod +x /workspaces/svelaxum/.agents/post_tool_hook.sh
echo "Antigravity CLI Hooks configured."

# Configure Antigravity CLI Permissions (Auto-Approve safe tools)
echo "Configuring Antigravity CLI Permissions..."
mkdir -p /home/vscode/.gemini/antigravity-cli
cat << 'EOF' > /home/vscode/.gemini/antigravity-cli/settings.json
{
  "permissions": {
    "allow": [
      "read_file(/workspaces/svelaxum)",
      "write_file(/workspaces/svelaxum)",
      "command(git)",
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
    ]
  }
}
EOF
echo "Antigravity CLI Permissions configured."


