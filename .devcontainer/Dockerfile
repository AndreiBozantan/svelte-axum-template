# syntax=docker/dockerfile:1

# --- Rust Toolchain (v1.95.0) ---
FROM rust:1.95.0-slim-bookworm@sha256:caaf9ca7acd474892186860307d6f28e51fdbc1a4eada459fcff81517cf46a36 AS rust-env
RUN rustup component add rust-analyzer clippy rustfmt

# --- Node.js (v24 LTS) ---
FROM node:24-bookworm-slim@sha256:03eae3ef7e88a9de535496fb488d67e02b9d96a063a8967bae657744ecd513f2 AS node-env

# --- Final Dev Container ---
FROM mcr.microsoft.com/devcontainers/base:bookworm@sha256:17e6cc517b483d1108b333d4c34352b0a21617f0117052e9b259d47113a9dc37

# Install system build tools (required for compiling native Rust/Node extensions)
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        pkg-config \
        libssl-dev \
        sqlite3 \
        libsqlite3-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy Node.js from official image
COPY --from=node-env /usr/local/bin/node /usr/local/bin/
COPY --from=node-env /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
    && ln -s /usr/local/lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx

# Copy uv (Python package manager)
COPY --from=ghcr.io/astral-sh/uv:0.11.8@sha256:3b7b60a81d3c57ef471703e5c83fd4aaa33abcd403596fb22ab07db85ae91347 /uv /usr/local/bin/uv

# Install Gemini CLI 
RUN npm install -g @google/gemini-cli

# Setup User and Shell
RUN usermod -s /usr/bin/zsh vscode
USER vscode

# Copy Rust toolchain into the vscode home directory with correct ownership
COPY --chown=vscode:vscode --from=rust-env /usr/local/cargo /home/vscode/.cargo
COPY --chown=vscode:vscode --from=rust-env /usr/local/rustup /home/vscode/.rustup

# 5. Set Environment Variables so tools are found in the PATH
ENV RUSTUP_HOME="/home/vscode/.rustup" \
    CARGO_HOME="/home/vscode/.cargo" \
    PATH="/home/vscode/.cargo/bin:/home/vscode/.local/bin:${PATH}"

# Install Semgrep using uv. The --mount=type=cache option is used to cache 
# the downloaded packages on the host machine, which speeds up subsequent 
# dev container builds by avoiding re-downloading the same packages.
# uid/gid=1000 matches the vscode user so the cache is writable.
RUN --mount=type=cache,target=/home/vscode/.cache/uv,uid=1000,gid=1000 \
    uv tool install semgrep

# Prepare volume mount points
# Create every directory that will be backed by a named Docker volume.
# Docker seeds a named volume from the image on first use only, so the dirs
# must exist with correct ownership before the volumes are mounted.
RUN mkdir -p \
  /home/vscode/.cargo/registry \
  /home/vscode/.cargo/git \
  /home/vscode/.npm \
  /home/vscode/.vscode-server

# Optional: customize the zsh shell for the vscode user.
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
RUN mkdir -p /home/vscode/.zsh_data \
    && sed -i \
        -e 's/ZSH_THEME="devcontainers"/ZSH_THEME="svelaxum"/' \
        -e 's/plugins=(git)/plugins=(git npm rust zsh-autosuggestions)/' \
        -e 's/# DISABLE_AUTO_UPDATE="true"/HISTFILE=~\/.zsh_data\/.zsh_history\nHISTSIZE=10000\nSAVEHIST=10000\nsetopt APPEND_HISTORY\nsetopt INC_APPEND_HISTORY\nsetopt SHARE_HISTORY/' \
        /home/vscode/.zshrc

# Generate shell completions for rustup, cargo, and uv, and place them in the Oh My Zsh completions directory.
RUN mkdir -p /home/vscode/.oh-my-zsh/completions \
    && rustup completions zsh > /home/vscode/.oh-my-zsh/completions/_rustup \
    && rustup completions zsh cargo > /home/vscode/.oh-my-zsh/completions/_cargo \
    && uv generate-shell-completion zsh > /home/vscode/.oh-my-zsh/completions/_uv

# Create the custom Oh My Zsh theme that shows the current directory and git branch in the prompt.
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

