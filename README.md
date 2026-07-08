# svelte-axum-template

Starting project template for a Rust + Svelte fullstack SPA. Backend: Axum + SQLite + sqlx. Frontend: Svelte 5 (runes) + Vite. Does not use SvelteKit.

Work in progress (new features coming), but should be usable as a starting point.

# Cloning the template
- Using cargo: `cargo install cargo-generate`, then `cargo generate AndreiBozantan/svelte-axum-template -n <your-project-name>`
- Using git: hit the green "Use this template" button on top of the repo, or use the `--template` option of the `gh` CLI.

# Running the project

The recommended dev environment is the VS Code devcontainer, which comes pre-configured with all toolchains, git hooks, and shell completions. Otherwise, install [NodeJs](https://nodejs.org/en/download/) and [Rust](https://www.rust-lang.org/tools/install) locally.

From the project root folder:
- `cargo xtask dev init` — one-time initialization (installs deps, git hooks, creates the database)
- `cargo xtask dev run` (or simply `cargo xtask dev`) — run in dev mode with hot reloading

The backend runs at `http://localhost:3000` and the frontend at `http://localhost:5173`. In dev mode, Vite proxies API requests to the backend, so the app is used via `http://localhost:5173`.

Run `cargo xtask --help` to see all available tasks (dev control, SQLx management, make targets, CI checks, prod).

# Release build

`cargo xtask make release` builds the frontend and backend in release mode. The frontend is built **first**, because its static files are embedded into the backend binary at compile time (via `rust-embed`), producing a single self-contained executable.

This means: whenever frontend changes should be reflected in the backend server on port `3000`, rebuild the frontend (`cd frontend && npm run build`) and recompile the backend. During normal development with `cargo xtask dev` this doesn't matter — the Vite dev server serves the frontend directly.

`cargo xtask make clean` removes all build artifacts including `node_modules`; run `cargo xtask dev init` again afterwards.

`cargo xtask make format` auto-formats both the backend Rust files (using `cargo fmt --all`) and the frontend files (using Prettier).

# Backend

- Located in `./backend`, organized using DDD-style bounded contexts (see `AGENTS.md` for the layout).
- Session auth with short-lived JWT access tokens and rotating refresh tokens, both in HttpOnly cookies; `Authorization: Bearer` is also supported for programmatic clients.
- Google OAuth2 SSO login (see setup below).
- API conventions (status codes, error shape, pagination) are documented in `docs/api/conventions.md`.

## Configuration

The backend is configured with TOML files in the `data/` directory:
- `configs.common.toml` — defaults shared by all environments
- `configs.development.toml` / `configs.production.toml` — per-environment overrides
- `configs.local.toml` — local overrides, git-ignored (put secrets here)

Values can also be overridden with environment variables, e.g. `APP__OAUTH__GOOGLE_CLIENT_ID`.

## Database migrations

Migrations live in `migrations/` and are embedded into the binary. To apply pending migrations:

```bash
cargo sqlx migrate run    # in development
./your-app migrate run    # in production (uses embedded migrations)
```

Do not copy the `migrations/` directory to production; the binary falls back to the embedded migrations when the directory is absent.

# Frontend

- Located in `./frontend`; includes login/logout, a secure page showing session info, and typed API call examples.
- The API client is generated from the backend's OpenAPI spec — `cargo xtask openapi` regenerates `openapi.json` and the typed client in `frontend/src/lib/generated/`. See `docs/api/codegen.md`.

# OAuth2 SSO Setup (Google)

## 1. Create Google OAuth2 credentials

1. Go to the [Google Cloud Console](https://console.cloud.google.com/) and create a new project.
2. Configure **APIs & Services > Google Auth platform**: fill in Branding (app name, support email), set Audience to **External**, and optionally add the `openid`, `userinfo.email`, and `userinfo.profile` scopes.
3. Create credentials: **+ Create Credentials > OAuth client ID**, type **Web application**, with:
   - Authorized JavaScript origins: `http://localhost:5173`
   - Authorized redirect URIs: `http://localhost:3000/api/oauth/google/callback`
4. Copy the generated **Client ID** and **Client Secret**.

## 2. Configure the backend

⚠️ Never commit OAuth secrets to git! Put them in `data/configs.local.toml` (git-ignored):

```toml
[oauth]
google_client_id = "your-client-id-here"
google_client_secret = "your-client-secret-here"
```

Alternatively, use the `APP__OAUTH__GOOGLE_CLIENT_ID` and `APP__OAUTH__GOOGLE_CLIENT_SECRET` environment variables.

## 3. Log in

Start the app (`cargo xtask dev run` or simply `cargo xtask dev`), open the login page, and click "Sign in with Google". OAuth users are stored in the same `users` table (`sso_provider` = "google", `sso_id` = Google user ID, `password_hash` = NULL) and get the same JWT tokens as password login, so all auth middleware works identically.
