# Semgrep Integration

Semgrep is a fast, open-source static analysis tool for finding bugs and enforcing code standards. This project integrates Semgrep to perform security analysis on both the Rust backend and Svelte frontend.

## Dev Container Support

Semgrep is **pre-installed** in the project's Dev Container. If you are using VS Code with the Remote - Containers extension, you don't need to install anything manually. The environment also includes the official Semgrep VS Code extension for real-time feedback.

## Local Usage (Outside Dev Container)

### 1. Installation

```bash
# install through pipx (https://pipx.pypa.io/stable/how-to/install-pipx/)
pipx install semgrep

# or, install through uv (https://docs.astral.sh/uv/)
uv tool install semgrep

# confirm installation succeeded by printing the currently installed version
semgrep --version
```

Log in to your Semgrep account. Running this command launches a browser window, but you can also use the link that's returned in the CLI to proceed:

```bash
semgrep login
```


### 2. Running Analysis

To scan the entire project:

```bash
cargo xtask lint-security
# or directly:
semgrep --config r/all
```

## Configuration

The configuration is kept very simple - just run all rules (`r/all`), both in the local setup (xtask) and in the GitHub workflow config. There is no custom rules file.

## CI/CD Integration

Semgrep is integrated into the CI/CD pipeline via GitHub Actions. It runs on every push and pull request to ensure no new security vulnerabilities are introduced.

The workflow is defined in `.github/workflows/semgrep.yml`.

## Exclusions

Files and directories like `target/`, `node_modules/`, and `dist/` are ignored via `.semgrepignore`.
