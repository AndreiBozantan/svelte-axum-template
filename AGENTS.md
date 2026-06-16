# SVELAXUM - Fullstack Webapp Template

Rust + Svelte fullstack template. Backend: Axum + SQLite + sqlx. Frontend: Svelte 5 (runes) + Vite.

Treat this project as a production-quality codebase - code design and implementation must meet production-grade standards.

Dev Env: VS Code devcontainer is the preferred development environment (pre-configured with Fish shell, toolchains, git hooks, and command autocompletion).

# REPO STRUCTURE

- Cargo.toml - workspace root with member [backend]
- frontend/ - Svelte 5 SPA with Vite
- backend/ - unified backend package containing platform and application code
- data/ - config files and SQLite database
- migrations/ - SQL migration files embedded via sqlx; main SQL schema is in migrations/01_initial_schema.sql
- xtask/ - Rust-based automation scripts for: env setup, dev scripts, git-hooks, release, CI
- .githooks/ - pre-commit and pre-push hook templates (copied via `cargo xtask setup-hooks`)

# BACKEND STRUCTURE

- backend/platform/ - platform library code (identity, shared, internal)
- backend/platform/identity - APIs and services for: users, tokens, auth, oauth
- backend/app/ - application specific API endpoints and corresponding services
- backend/test/ - unit and integration tests (without the 's' suffix to prevent separate integration test binary builds, reducing binary count to exactly 1)

# BACKEND DESIGN

- the module tree is declared in a single (non-idiomatic) file at backend/main.rs to avoid polluting file tree with mod.rs files
- the project is organized to use a DDD pattern for organizing platform and app features
- each bounded context (e.g. backend/platform/identity) has sub-features: auth, oauth, tokens, users
- each subfeature has 3 main files: subfeature_api.rs, subfeature_db.rs, subfeature_service.rs and optionally subfeature_tests.rs and subfeature_utils.rs.
- backend/platform/identity/users/ - can be used as a template when implementing new features

# BACKEND CODING STYLE

- imports: `use module;` and then qualify types with `module::MyType` in the code; avoid `use module::MyType`.
- avoid map_err and use error conversions instead
- use chaining of method calls when possible, in a functional programming style
- use validator::Validate to validate the inputs
- structured logging: log message must be short, lowercase, using underscores, no spaces; use key-value fields; example:
  `warn!(user_id = user.id.0, error = %err, "password_rehash_failed");`
- run `cargo clippy --workspace --all-targets` after every change and fix the issues
- use idiomatic Rust and work like an world-expert Rust senior software engineer
- prioritize following already existing patterns from the code

# GIT HOOKS

- configured in `.githooks/` and installed via `cargo xtask setup-hooks` (also executed with `cargo xtask dev-init`)
- `pre-commit`: runs `cargo fmt`, `cargo clippy`, and `sqlx prepare --check` if backend/xtask changes are staged; runs `prettier` and `svelte-check` if frontend changes are staged
- `pre-push`: runs backend tests (`cargo test`) and frontend tests (`vitest`) selectively based on what directories have changed
