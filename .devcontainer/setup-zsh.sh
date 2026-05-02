#!/usr/bin/env bash
set -e

echo "Configuring Zsh environment..."

# 1. Install zsh-autosuggestions plugin
ZSH_PLUGINS_DIR="/home/vscode/.oh-my-zsh/custom/plugins/zsh-autosuggestions"
if [ ! -d "$ZSH_PLUGINS_DIR" ]; then
    git clone https://github.com/zsh-users/zsh-autosuggestions "$ZSH_PLUGINS_DIR"
fi

# 2. Configure zshrc 
mkdir -p /home/vscode/.zsh_data
if [ -f "/home/vscode/.zshrc" ]; then
    sed -i \
        -e 's/ZSH_THEME="devcontainers"/ZSH_THEME="svelaxum"/' \
        -e 's/plugins=(git)/plugins=(git npm rust zsh-autosuggestions)/' \
        -e 's/# DISABLE_AUTO_UPDATE="true"/HISTFILE=~\/.zsh_data\/.zsh_history\nHISTSIZE=10000\nSAVEHIST=10000\nsetopt APPEND_HISTORY\nsetopt INC_APPEND_HISTORY\nsetopt SHARE_HISTORY/' \
        /home/vscode/.zshrc
fi

# 3. Generate shell completions
mkdir -p /home/vscode/.oh-my-zsh/completions
rustup completions zsh > /home/vscode/.oh-my-zsh/completions/_rustup
rustup completions zsh cargo > /home/vscode/.oh-my-zsh/completions/_cargo
uv generate-shell-completion zsh > /home/vscode/.oh-my-zsh/completions/_uv

# 4. Create custom svelaxum theme
THEME_DIR="/home/vscode/.oh-my-zsh/custom/themes/svelaxum.zsh-theme"
cat > "$THEME_DIR" << 'EOF'
ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE="fg=243"

setopt PROMPT_SUBST

_svelaxum_precmd() {
  local dir="${(%):-"%~"}"
  local branch="$(git rev-parse --abbrev-ref HEAD 2>/dev/null)"

  if [[ -n "$branch" ]]; then
    local pad=$(( COLUMNS - ${#dir} - ${#branch} ))
    [[ $pad -lt 1 ]] && pad=1
    print -P "%B%F{27}${dir}%f%b${(r:$pad:: :)}%F{green}${branch}%f"
  else
    print -P "%B%F{27}${dir}%f%b"
  fi
}

precmd_functions+=(_svelaxum_precmd)

PROMPT='❯ '
EOF

echo "Zsh configuration complete."