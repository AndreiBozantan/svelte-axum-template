# Starter Student Tasks

## 1. Frontend: Finish SPA Routing or Adopt `svelte-spa-router`

- **GitHub Issue:** [#205](https://github.com/AndreiBozantan/svelte-axum-template/issues/205)
- **Files to edit:**
    - [AppSidebar.svelte](frontend/src/AppSidebar.svelte)
    - [App.svelte](frontend/src/App.svelte)
    - [AppPages.svelte.ts](frontend/src/AppPages.svelte.ts)
- **Description:**
  Currently, clicking nav links in the sidebar triggers a full browser reload, destroying all client-side state and causing redundant authentication fetches. The template's SPA routing mechanism is only half-implemented. You will implement a full routing solution—either by finishing the hand-rolled custom router (intercepting `<a>` click events, preventing defaults, updating history state, and resolving paths/404s cleanly) or integrating the already-installed `svelte-spa-router`.
- **Educational Value:** A solid architectural task that teaches routing concepts, event interception, and Svelte 5 state management. The performance gain is immediate and highly visible.
- **Estimated Time:** 45–60 minutes.

## 2. Tooling & DX: Configure and Enforce ESLint and Rust Workspace Lints

- **GitHub Issue:** [#207](https://github.com/AndreiBozantan/svelte-axum-template/issues/207)
- **Files to edit:**
    - [package.json](frontend/package.json)
    - `.githooks/pre-commit`
    - Root [Cargo.toml](Cargo.toml)
- **Description:**
  The codebase has format checks, but lacks lint-level code style rule enforcement. You will set up ESLint (`typescript-eslint` and `eslint-plugin-svelte`) on the frontend, wire it into both the local git pre-commit hook and the CI pipeline, and introduce a modern `[workspace.lints]` block in the backend [Cargo.toml](Cargo.toml) to enforce unified Rust style policies. Finally, you will run the checkers and resolve any styling errors they flag.
- **Educational Value:** Helps students get comfortable with build chains, Git hooks, and workspace-level project settings.
- **Estimated Time:** 30–45 minutes.

## 3. Backend: Implement Fail-Fast Configuration Validation at Startup

- **GitHub Issue:** [#204](https://github.com/AndreiBozantan/svelte-axum-template/issues/204)
- **Files to edit:**
    - [config.rs](backend/platform/shared/config.rs)
    - [server.rs](backend/server.rs)
- **Description:**
  Right now, the server will start up silently even if required configuration fields are missing or invalid (e.g. invalid DB URL, incomplete Google OAuth client credentials), which leads to failures later when users hit those routes. You will implement a robust validation method `AppSettings::validate()` that is executed on startup, verifying settings completeness and strength (especially in production), and writing unit tests to assert validation failures.
- **Educational Value:** Excellent Rust backend task. It teaches validation patterns, parsing, and error propagation. Writing unit tests for configuration edge cases is highly structured.
- **Estimated Time:** 30–50 minutes.

## 4. Backend: Offload Argon2 Password Hashing to `spawn_blocking`

- **GitHub Issue:** [#228](https://github.com/AndreiBozantan/svelte-axum-template/issues/228)
- **Files to edit:**
    - [crypto.rs](backend/platform/shared/crypto.rs)
    - [auth_service.rs](backend/platform/identity/auth/auth_service.rs)
- **Description:**
  Currently, Argon2id password hashing and verification are executed inline within the async request handlers. Because Argon2 is CPU-intensive (taking tens of milliseconds per call), executing it directly on a Tokio worker thread blocks that worker and can starve the async executor under concurrent login or registration load. You will wrap these CPU-bound operations in `tokio::task::spawn_blocking` to ensure Tokio's async worker threads remain free to process other concurrent I/O.
- **Educational Value:** Teaches async scheduling concepts, the distinction between CPU-bound and I/O-bound tasks in Rust, and preventing executor starvation under load.
- **Estimated Time:** 15–20 minutes.

## 5. Backend & Ops: Configure SQLite Durability Settings and Connection Pool Timeout

- **GitHub Issue:** [#229](https://github.com/AndreiBozantan/svelte-axum-template/issues/229)
- **Files to edit:**
    - [db.rs](backend/platform/shared/db.rs)
    - [operations.md](docs/design/operations.md)
- **Description:**
  The SQLite configuration uses write-ahead logging (WAL) but does not explicitly configure the `synchronous` pragma. To guarantee durability and prevent unnecessary fsync overhead, you will explicitly set `PRAGMA synchronous = NORMAL` in the database connection options. Additionally, you will set a connection pool acquire timeout, and document the SQLite operational choices (WAL, synchronous mode, and pool settings) along with a backup/recovery strategy in the operations design document.
- **Educational Value:** Covers SQLite WAL performance tuning, connection pool configuration, database durability guarantees, and writing operational runbooks.
- **Estimated Time:** 20–30 minutes.

## 6. Backend & Observability: Implement Request ID Generation and Propagation

- **GitHub Issue:** [#230](https://github.com/AndreiBozantan/svelte-axum-template/issues/230)
- **Files to edit:**
    - [router.rs](backend/router.rs)
    - [conventions.md](docs/api/conventions.md)
- **Description:**
  The server lacks a mechanism to correlate multiple log lines generated by a single HTTP request. You will integrate `tower_http::request_id` to generate and propagate an `X-Request-ID` header. This request ID must be included in the tracing span so all structured logs for the request share the ID, and the header must be returned in the HTTP response so clients can reference it. Finally, update the API conventions document to mark the request ID convention as fully implemented.
- **Educational Value:** Introduces request correlation, structured tracing, and context propagation in multi-layered HTTP services.
- **Estimated Time:** 20–35 minutes.

## 7. Backend & Resilience: Supervise and Log Background Cleanup Tasks

- **GitHub Issue:** [#231](https://github.com/AndreiBozantan/svelte-axum-template/issues/231)
- **Files to edit:**
    - [server.rs](backend/server.rs)
- **Description:**
  The server spawns background loops to clean up expired refresh tokens and rate-limiter entries. If either of these loops panics, the task terminates silently, halting all future cleanup cycles without notifying the system. You will wrap these background loop bodies with panic recovery, log any unexpected task exits, and implement a basic supervision/restart pattern to ensure background tasks remain healthy and resilient.
- **Educational Value:** Teaches supervision trees, panic recovery/handling in background Tokio tasks, and defensive programming for daemon threads.
- **Estimated Time:** 15–25 minutes.

## 8. DevOps: Add Container Healthchecks and Modernize Compose Configuration

- **GitHub Issue:** [#232](https://github.com/AndreiBozantan/svelte-axum-template/issues/232)
- **Files to edit:**
    - [Dockerfile](Dockerfile)
    - [docker-compose.yml](docker-compose.yml)
- **Description:**
  The application exposes a `/health` endpoint, but the containerization setup does not monitor it. You will define a `healthcheck` block in `docker-compose.yml` to monitor the application status. Because the production image is built `FROM scratch` and lacks curl/sh, you will need to determine how to run the healthcheck probe (e.g. by using an orchestrator-level HTTP probe or implementing a light health subcommand in the app binary). At the same time, clean up the obsolete `version` key in `docker-compose.yml`.
- **Educational Value:** Covers container health monitoring, building and running checks on minimal `scratch` images, and maintaining modern Compose configuration files.
- **Estimated Time:** 20–30 minutes.

## 9. Backend & Performance: Enable HTTP Response Compression

- **GitHub Issue:** [#233](https://github.com/AndreiBozantan/svelte-axum-template/issues/233)
- **Files to edit:**
    - [router.rs](backend/router.rs)
- **Description:**
  While static assets are cached and hashed correctly, the server currently serves HTML, JS, CSS, and JSON payloads completely uncompressed. You will configure `tower_http::compression::CompressionLayer` on the router to support dynamic compression (gzip, brotli, etc.) for text-based and API responses, reducing bandwidth consumption and improving page load latency.
- **Educational Value:** Illustrates web performance optimization techniques and middleware integration in Rust HTTP routers.
- **Estimated Time:** 10–15 minutes.

## 10. Backend & Ops: Secure Diagnostic Endpoints and Separate Liveness/Readiness Probes

- **GitHub Issue:** [#234](https://github.com/AndreiBozantan/svelte-axum-template/issues/234)
- **Files to edit:**
    - [router.rs](backend/router.rs)
    - [config.rs](backend/platform/shared/config.rs)
    - [operations.md](docs/design/operations.md)
- **Description:**
  The diagnostic endpoint `/health?panic=true` is currently publicly accessible in all environments, including production, exposing the application to denial-of-service noise. Additionally, liveness and readiness checks are combined into a single DB-ping endpoint. You will split `/health` (simple liveness) from `/ready` (dependency readiness, checking the DB connection), restrict the `panic=true` query parameter to non-production environments using configuration checks, and document the health check semantics in `docs/design/operations.md`.
- **Educational Value:** Covers API security, environment gating, and designing Kubernetes-compatible liveness and readiness probe architectures.
- **Estimated Time:** 25–40 minutes.
