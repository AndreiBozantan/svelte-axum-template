# SVELAXUM - Fullstack Webapp Template

Rust + Svelte fullstack template. Backend: Axum + SQLite + sqlx. Frontend: Svelte 5 (runes) + Vite.

Treat this project as a production-quality codebase - code design and implementation must meet production-grade standards.

Dev Env: VS Code devcontainer is the preferred development environment (pre-configured with Fish shell, toolchains, git hooks, and command autocompletion).

# REPO STRUCTURE

- Cargo.toml - workspace root with member [backend]
- frontend/ - Svelte 5 SPA with Vite
- backend/ - unified backend package containing platform and application code
- data/ - config files (`configs.common.toml` + per-env + git-ignored `configs.local.toml`) and SQLite database
- migrations/ - SQL migration files embedded via sqlx; main SQL schema is in migrations/01_initial_schema.sql
- xtask/ - Rust-based automation scripts; run `cargo xtask help` for the full command list
- docs/ - API conventions, codegen, and devops docs
- .githooks/ - pre-commit and pre-push hook templates (copied via `cargo xtask dev init`)
- .agents/skills/ - agent skills (see below)

# WORKFLOW

- when asked a question: answer, explain, give alternative solution, do NOT change code until told to proceed
- do not run git commit, unless explicitly asked
- implement larger changes as a sequence of small, individually reviewable steps and stop after each step for review
- if the user edited files since your last read, re-read them before making further changes
- ask clarifying questions when the request is ambiguous, before writing code
- after completing code changes run `cargo -q xtask check backend` and/or `cargo -q xtask check frontend` and fix any issues
- when introducing new code write new tests, including a test which fails before fixing code issues

# CODING STYLE

- purity: domain logic functions should be pure (no direct I/O, DB queries, random or system clock calls)
- functional idioms: prefer method chaining and composition, avoiding intermediate variables and imperative loops with mutable state
- separation of concerns: I/O, DB access, and HTTP handling should be separate from domain logic
- type complexity: avoid deeply nested generics or trait bounds unless justified
- cyclomatic complexity: if a function has more than ~7 decision branches, recommend splitting (excluding exhaustive `match` on sealed enums)
- nesting depth: logic buried 3+ levels in is hard to read and usually means errors aren't being surfaced properly
- coupling: avoid reaching into other modules' internals and favor dependency injection
- single line comments should start with lowercase

# BACKEND STRUCTURE

- backend/platform/ - platform library code (identity, shared, internal)
- backend/platform/identity - APIs and services for: users, tokens, auth, oauth
- backend/platform/shared - cross-cutting code: api error types, config, jwt, cookies, crypto, rate limiter
- backend/app/ - application specific API endpoints and corresponding services
- backend/test/ - unit and integration tests (without the 's' suffix to prevent separate integration test binary builds, reducing binary count to exactly 1)

# BACKEND DESIGN

- the module tree is declared in a single (non-idiomatic) file at backend/main.rs to avoid polluting file tree with mod.rs files
- the project is organized to use a DDD pattern for organizing platform and app features
- each bounded context (e.g. backend/platform/identity) has sub-features: auth, oauth, tokens, users
- each subfeature has 3 main files: subfeature_api.rs, subfeature_db.rs, subfeature_service.rs and optionally subfeature_tests.rs and subfeature_utils.rs.
- backend/platform/identity/users/ - can be used as a template when implementing new features

# BACKEND CODING STYLE

- use idiomatic Rust and work like an world-expert Rust senior software engineer
- prioritize following already existing patterns from the surrounding code
- avoid map_err and use error conversions instead
- prefer early returns and ?-propagation over deeply nested if let / match chains
- use validator::Validate to validate the inputs
- prefer newtype wrappers over raw primitives for domain IDs
- avoid unnecessary `.clone()` as a shortcut for fixing borrow issues — it's often a symptom of a structural problem
- avoid multiple grouped imports in brackets on the same line
- structured logging: log message must be short, lowercase, using underscores, no spaces; use key-value fields; example:
  `warn!(user_id = user.id.0, error = %err, "password_rehash_failed");`

# API & CODEGEN

- API conventions (status codes, error shape, REST rules) are in docs/api/conventions.md - all endpoints must follow them
- the TypeScript API client is generated from the backend OpenAPI spec; see docs/api/codegen.md
- after adding or changing an endpoint: annotate handlers/DTOs with utoipa, then run `cargo xtask make openapi` to regenerate openapi.json and the frontend client
- never hand-edit files under frontend/src/lib/generated/
- frontend code calls the API via the generated client (e.g. `api.auth.login(...)` from `$lib/generated/endpoints.ts`), never via raw fetch

# GIT HOOKS

- configured in `.githooks/` and installed via `cargo xtask dev init`
- `pre-commit` (`cargo -q xtask check commit`)
    - backend: formatting, openapi spec drift;
    - frontend: formatting (prettier), linting (eslint), client drift;
    - run `cargo xtask make format` to automatically format all files;
- `pre-push` (`cargo -q xtask check push`)
    - backend: lints (clippy), sqlx prep, tests, openapi drift;
    - frontend: lints (eslint), diagnostics (svelte-check, tsc), tests, client drift;

# CUSTOM AGENT SKILLS

Skills are stored in the agent-agnostic `.agents/skills/` directory. Agent-specific shims (e.g. a git-ignored `CLAUDE.md` and `.claude/` pointing here) are generated locally by `.devcontainer/setup-env.sh` and must not be committed.

- `review-backend`: detailed code review criteria for the Rust backend code; trigger when review or feedback is requested.
- `review-frontend`: detailed code review criteria for the Svelte 5 frontend code; trigger when review or feedback is requested.
- `triage-review-finding`: verify a pasted code review finding against the actual code before acting on it.
