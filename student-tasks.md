# Starter Student Tasks

### 1. Frontend: Finish SPA Routing or Adopt `svelte-spa-router`

- **GitHub Issue:** [#205](https://github.com/AndreiBozantan/svelte-axum-template/issues/205)
- **Files to edit:**
    - [AppSidebar.svelte](frontend/src/AppSidebar.svelte)
    - [App.svelte](frontend/src/App.svelte)
    - [AppPages.svelte.ts](frontend/src/AppPages.svelte.ts)
- **Description:**
  Currently, clicking nav links in the sidebar triggers a full browser reload, destroying all client-side state and causing redundant authentication fetches. The template's SPA routing mechanism is only half-implemented. You will implement a full routing solution—either by finishing the hand-rolled custom router (intercepting `<a>` click events, preventing defaults, updating history state, and resolving paths/404s cleanly) or integrating the already-installed `svelte-spa-router`.
- **Educational Value:** A solid architectural task that teaches routing concepts, event interception, and Svelte 5 state management. The performance gain is immediate and highly visible.
- **Estimated Time:** 45–60 minutes.

### 2. Tooling & DX: Configure and Enforce ESLint and Rust Workspace Lints

- **GitHub Issue:** [#207](https://github.com/AndreiBozantan/svelte-axum-template/issues/207)
- **Files to edit:**
    - [package.json](frontend/package.json)
    - `.githooks/pre-commit`
    - Root [Cargo.toml](Cargo.toml)
- **Description:**
  The codebase has format checks, but lacks lint-level code style rule enforcement. You will set up ESLint (`typescript-eslint` and `eslint-plugin-svelte`) on the frontend, wire it into both the local git pre-commit hook and the CI pipeline, and introduce a modern `[workspace.lints]` block in the backend [Cargo.toml](Cargo.toml) to enforce unified Rust style policies. Finally, you will run the checkers and resolve any styling errors they flag.
- **Educational Value:** Helps students get comfortable with build chains, Git hooks, and workspace-level project settings.
- **Estimated Time:** 30–45 minutes.

### 3. Backend: Implement Fail-Fast Configuration Validation at Startup

- **GitHub Issue:** [#204](https://github.com/AndreiBozantan/svelte-axum-template/issues/204)
- **Files to edit:**
    - [config.rs](backend/platform/shared/config.rs)
    - [server.rs](backend/server.rs)
- **Description:**
  Right now, the server will start up silently even if required configuration fields are missing or invalid (e.g. invalid DB URL, incomplete Google OAuth client credentials), which leads to failures later when users hit those routes. You will implement a robust validation method `AppSettings::validate()` that is executed on startup, verifying settings completeness and strength (especially in production), and writing unit tests to assert validation failures.
- **Educational Value:** Excellent Rust backend task. It teaches validation patterns, parsing, and error propagation. Writing unit tests for configuration edge cases is highly structured.
- **Estimated Time:** 30–50 minutes.

### 4. Devops/Runtime: Implement Graceful Shutdown on SIGTERM

- **GitHub Issue:** [#200](https://github.com/AndreiBozantan/svelte-axum-template/issues/200)
- **File to edit:**
    - [server.rs](backend/server.rs)
- **Description:**
  The application server shuts down gracefully only when receiving Ctrl+C (`SIGINT`), but Docker and Kubernetes orchestrators terminate containers by sending `SIGTERM`. Without intercepting `SIGTERM`, the app is abruptly killed, dropping active database transactions and in-flight HTTP requests. You will rewrite the server shutdown signal listener to support both signals on Unix-like operating systems while preserving a safe fallback for Windows environments.
- **Educational Value:** A crucial DevOps/Runtime task that teaches asynchronous signal handling in Rust using `tokio::signal`.
- **Estimated Time:** 20–30 minutes.

### 5. Backend Security: Add Request Body Limits and Field Constraints

- **GitHub Issue:** [#198](https://github.com/AndreiBozantan/svelte-axum-template/issues/198)
- **Files to edit:**
    - [router.rs](backend/router.rs)
    - [auth_api.rs](backend/platform/identity/auth/auth_api.rs)
- **Description:**
  Unbounded payloads pose serious security risks (e.g. memory exhaustion or CPU-exhaustion DoS via very large passwords passed to Argon2). You will configure a default body limit layer in the Axum router (`DefaultBodyLimit::max(64KB)`) and apply strict min/max validation rules to DTO fields like `RegisterRequest` (first name, last name, email, and password) using the Rust `validator` crate.
- **Educational Value:** Very structured and clear validation logic. It gets students familiar with web service request-handling pipelines, middleware configuration in Axum, and input validation design patterns.
- **Estimated Time:** 30–45 minutes.
