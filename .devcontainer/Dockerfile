# syntax=docker/dockerfile:1
FROM mcr.microsoft.com/devcontainers/base:bookworm

# System dependencies + Node.js 24 
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        curl \
        build-essential \
        pkg-config \
        libssl-dev \
        sqlite3 \
        libsqlite3-dev \
    && curl -fsSL https://deb.nodesource.com/setup_24.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Google Gemini CLI for agentic coding
RUN npm install -g @google/gemini-cli

# uv 
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# sets the user's login shell to zsh
RUN usermod -s /usr/bin/zsh vscode

# Install Rust, Semgrep (with uv), and configure cache directories, as vscode user.
# Running as vscode ensures the installed tools and created directories have correct 
# ownership (uid/gid 1000) for seamless use and caching in the devcontainer environment.
USER vscode


# Install Rust via rustup into the vscode user's home directory (~/.cargo, ~/.rustup).
# --no-modify-path prevents rustup from editing shell profiles; PATH is instead set
# explicitly via ENV so it applies across all layers and processes in the container.
# Also installs rust-analyzer (LSP), clippy (linter), and rustfmt (formatter).
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --no-modify-path \
    && /home/vscode/.cargo/bin/rustup component add rust-analyzer clippy rustfmt

ENV PATH="/home/vscode/.cargo/bin:/home/vscode/.local/bin:${PATH}"

# --mount=type=cache persists the uv download cache on the host across rebuilds,
# so semgrep's packages are not re-downloaded every time the image is rebuilt.
# uid/gid=1000 matches the vscode user so the cache is writable.
RUN --mount=type=cache,target=/home/vscode/.cache/uv,uid=1000,gid=1000 \
    uv tool install semgrep

# Create every directory that will be backed by a named Docker volume.
# Docker seeds a named volume from the image on first use only, so the dirs
# must exist with correct ownership before the volumes are mounted.
#
#   ~/.cargo/registry  – crate source tarballs
#   ~/.cargo/git       – git-sourced crate checkouts
#   ~/.npm             – npm content-addressable package cache
#   ~/.vscode-server   – VS Code Server, extensions, CodeLLDB
RUN mkdir -p \
        /home/vscode/.cargo/registry \
        /home/vscode/.cargo/git \
        /home/vscode/.npm \
        /home/vscode/.vscode-server


# Configure Oh My Zsh with a custom theme and plugins. 
RUN mkdir -p /home/vscode/.zsh_data


# Create a custom Oh My Zsh theme that shows the current directory and git branch in the prompt.
RUN cat > /home/vscode/.oh-my-zsh/custom/themes/svelaxum.zsh-theme << 'EOF'
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

# Install the zsh-autosuggestions plugin by cloning its repository into the Oh My Zsh custom plugins directory.
RUN git clone https://github.com/zsh-users/zsh-autosuggestions \
        /home/vscode/.oh-my-zsh/custom/plugins/zsh-autosuggestions

# Set the custom zsh theme.
# Configure plugins for git aliases (git), npm completion (npm),
# cargo/rustup completion (rust), and fish-style history suggestions (zsh-autosuggestions).
# Note: zsh-autosuggestions must be installed separately before being listed here.
# Replace the placeholder DISABLE_AUTO_UPDATE line with zsh history config:
# store history in a shared file, keep 10,000 entries, and write each command
# immediately (INC_APPEND_HISTORY) and share it across all active sessions (SHARE_HISTORY).
RUN sed -i \
        -e 's/ZSH_THEME="devcontainers"/ZSH_THEME="svelaxum"/' \
        -e 's/plugins=(git)/plugins=(git npm rust zsh-autosuggestions)/' \
        -e 's/# DISABLE_AUTO_UPDATE="true"/HISTFILE=~\/.zsh_data\/.zsh_history\nHISTSIZE=10000\nSAVEHIST=10000\nsetopt APPEND_HISTORY\nsetopt INC_APPEND_HISTORY\nsetopt SHARE_HISTORY/' \
        /home/vscode/.zshrc

# Generate shell completions for rustup, cargo, and uv, and place them in the Oh My Zsh completions directory.
RUN mkdir -p /home/vscode/.oh-my-zsh/completions \
    && rustup completions zsh > /home/vscode/.oh-my-zsh/completions/_rustup \
    && rustup completions zsh cargo > /home/vscode/.oh-my-zsh/completions/_cargo \
    && uv generate-shell-completion zsh > /home/vscode/.oh-my-zsh/completions/_uv
