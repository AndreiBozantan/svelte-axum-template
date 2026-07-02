# Svelaxum Code Review — Findings Index

Repo-wide review conducted per `docs/misc/project-review.md`, using the project's
`review-backend` and `review-frontend` criteria. Each file below covers one review
area and is written so a GitHub issue can be created directly from each finding.

Severity legend: **Critical** (exploitable/data-loss/prod-breaking), **Important**
(should fix before real users), **Minor** (polish / hygiene).

## Files

- [01 — Authentication & Session Management](01-authentication-session.md)
- [02 — Authorization & Access Control](02-authorization-access-control.md)
- [03 — Input Validation & Injection](03-input-validation-injection.md)
- [04 — Secrets & Sensitive Data](04-scrts-sensitive-data.md)
- [05 — HTTP & Transport Security](05-http-transport-security.md)
- [06 — Dependency & Supply Chain](06-dependency-supply-chain.md)
- [07 — Code Structure & Architecture](07-code-structure-architecture.md)
- [08 — Rust Code Quality & Idioms](08-rust-code-quality.md)
- [09 — Frontend Code Quality & Svelte Idioms](09-frontend-code-quality.md)
- [10 — Database & Data Layer](10-database-data-layer.md)
- [11 — API Design](11-api-design.md)
- [12 — Testing](12-testing.md)
- [13 — Error Handling & Resilience](13-error-handling-resilience.md)
- [14 — Logging & Observability](14-logging-observability.md)
- [15 — Configuration & Environment](15-configuration-environment.md)
- [16 — Containerization & Deployment](16-containerization-deployment.md)
- [17 — CI/CD](17-cicd.md)
- [18 — Documentation & DX](18-documentation-dx.md)
- [19 — Performance & Scalability](19-performance-scalability.md)
- [20 — Business Logic Correctness](20-business-logic-correctness.md)
- [21 — General Code Hygiene](21-general-hygiene.md)

## Top issues (start here)

1. **`GET /api/users` leaks every user in the shared default tenant** — all self-signup
   and SSO users are created under `tenant_id = 0`, and any authenticated user can list
   that tenant. Cross-account email/PII disclosure with no admin gating. See
   [02](02-authorization-access-control.md).
2. **Committed base config runs the app in `development` mode** — `configs.common.toml`
   sets `env = "development"`, which seeds test data and enables debug logging. A deploy
   that ships the repo config (or omits `configs.production.toml`) runs non-prod behavior
   in prod. See [15](15-configuration-environment.md).
3. **`isAdmin` is computed from `user.id === 1`** on the frontend, but the seeded system
   admin is `id = 0`, and `id = 1` is just the first-registered ordinary user. Wrong user
   is shown admin UI. See [09](09-frontend-code-quality.md) / [20](20-business-logic-correctness.md).
4. **Duplicated `/api/api/sample` route path** (double `/api`) ships in the OpenAPI spec
   and generated client. See [11](11-api-design.md).
5. **`Logout.svelte` renders `{AppState.user}`** (the whole object) instead of the email.
   See [09](09-frontend-code-quality.md).

## What is already solid

- Argon2id with sane parameters, constant-time comparisons, dummy-hash timing defense,
  and password-hash rehash-on-login.
- Refresh-token rotation with reuse/breach detection and a grace period for concurrency;
  covered by focused tests.
- JWT algorithm pinned to HS256 with explicit `validate_exp`; `__Host-`/`__Secure-` cookie
  prefixes, `HttpOnly`, `Secure`, `SameSite=Strict` on token cookies.
- Parameterized SQL everywhere via `sqlx::query!`; tenant-scoped queries in the repository.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` passes clean;
  `npm audit` reports 0 vulnerabilities.
- Hardened runtime: `scratch` image, non-root, read-only rootfs, `cap_drop: ALL`,
  `no-new-privileges`.
