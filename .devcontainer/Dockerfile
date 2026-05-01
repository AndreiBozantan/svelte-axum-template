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

RUN npm install -g @google/gemini-cli

# uv 
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Rust, Semgrep, and cache directories (as vscode) 
# Installing as vscode keeps CARGO_HOME at /home/vscode/.cargo, which is where
# the named volume mounts in devcontainer.json point. No permission fixes needed.
USER vscode

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