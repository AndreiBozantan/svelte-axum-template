# Project Overview

The app was written by a junior developer with the help of low-quality AI agents like Cursor Composer and local AI models like Qwen 3.5, in a hurry.
The codebase may contain subtle bugs, security vulnerabilities, anti-patterns, architectural flaws and various shortcuts.
The target quality bar is very high: the code must be production-ready for a commercial SaaS product with paying customers, where security, reliability, and maintainability are non-negotiable.

- Backend: Rust 2024 edition, Axum 0.8, SQLite via sqlx 0.8, jsonwebtoken, argon2, oauth2
- Frontend: Svelte 5 (runes API), Vite 8, TypeScript, no SvelteKit
- Auth: JWT (access + refresh tokens in HttpOnly cookies), Google OAuth2 SSO, Argon2 password hashing
- Database: SQLite with WAL mode, embedded migrations via sqlx
- Deployment: Docker, frontend assets embedded in binary via rust-embed
- Config: Multi-layer TOML (common, environment-specific, local overrides, env vars)

# Task

Conduct a thorough, critical, adversarial and constructive code review.
Do not assume best practices were followed — verify everything against the actual code.
Analyze the code from the perspective of a staff/principal level software engineer with expert-level knowledge in the corresponding domain.

For each review area below, identify issues, explain why they are problems, and suggest concrete improvements.
For each area, create corresponding file under the `code-review-findings` folder, with the issue including:

- Severity: Critical / Important / Minor
- Location: file path and line range if applicable
- Finding: a clear description of what is wrong or missing
- Risk: why this matters (security, reliability, maintainability, scalability)
- Recommendation: a concrete, actionable fix

# Review Areas

## 1. Authentication & Session Management

- JWT implementation: token generation, validation, algorithm pinning (no `alg: none` or weak HMAC), signature verification, expiry, key rotation readiness
- Cookie security: HttpOnly, Secure, SameSite flags, path scoping, Max-Age correctness
- Refresh token flow: storage, revocation, reuse detection, rotation strategy, cleanup of expired tokens
- Password handling: hashing algorithm and parameters, resistance to timing-based user enumeration in the login flow, password policy; are passwords ever logged?
- OAuth2/SSO: state parameter validation (CSRF), PKCE, redirect URI whitelisting, open redirect prevention, scope minimization, token handling and storage
- Account lockout: threshold, window duration, reset behavior, user feedback
- Session management: session fixation prevention, concurrent session handling, logout completeness (token revocation)
- Frontend token/session handling: evaluate the token storage strategy against XSS and CSRF threat models — is any token material exposed to JavaScript, and is the chosen approach the most secure available option? Token refresh coordination — behavior under concurrent 401s, no duplicate refresh requests or retry storms, clean logout on refresh failure
- Authentication bypass: missing middleware on routes, incorrect route ordering in Axum, TOCTOU race conditions on session checks
- Cryptography: strength of RNGs and hash functions, absence of weak algorithms

## 2. Authorization & Access Control

- Consistent per-route, per-resource authorization enforcement — beyond just authentication
- Privilege escalation paths (e.g., ID manipulation to access another user's data)
- Multi-tenancy isolation (if the data model is multi-tenant): tenant scoping enforced on all queries
- Admin/internal endpoints protected separately from user-facing ones
- Frontend-enforced access controls replicated and enforced on the backend

## 3. Input Validation & Injection

- All user-supplied input validated and sanitized before use; email normalization
- SQL injection: all queries parameterized, no string interpolation or sqlx misuse
- XSS: `@html` usages or unsafe DOM manipulation in the Svelte frontend
- Path traversal: embedded static asset serving and SPA fallback path handling
- JSON payloads size-limited to prevent DoS
- Numeric and enum inputs bounds-checked before use in business logic

## 4. Secrets & Sensitive Data

- Secrets (JWT secrets, OAuth client secrets, DB credentials, API keys) hardcoded in source or config files?
- `.env` files or secrets committed to the repository? Is `.gitignore` complete?
- Secrets logged, included in error messages, or returned in API responses?
- PII (names, emails, IDs) logged unnecessarily?
- Sensitive data encrypted at rest and in transit; database backups encrypted?

## 5. HTTP & Transport Security

- HTTPS enforced everywhere; HTTP→HTTPS redirection
- Security headers: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, Referrer-Policy, Permissions-Policy
- CORS configured correctly — origins whitelisted, not `*` in production
- Rate limiting on authentication endpoints and other sensitive actions; rate limiter implementation correctness (keying, memory growth, behavior behind proxies)
- CSRF mitigations where applicable (especially for cookie-based auth)

## 6. Dependency & Supply Chain

- `Cargo.lock` and `package-lock.json` committed
- Known vulnerable dependencies (`cargo audit`, `npm audit`)
- Dependencies pinned appropriately vs loose semver ranges
- Process for dependency updates (Dependabot, Renovate)
- Abandoned or unmaintained dependencies, single-maintainer risk
- Dev dependencies separated from production dependencies
- License compliance of dependencies

## 7. Code Structure & Architecture

- Clear, cohesive modules/layers with well-defined responsibilities (HTTP handling, business logic, data access)
- Crate/workspace and package boundaries: does the current split earn its complexity, or should it be restructured? No circular dependencies
- Separation of concerns: HTTP concerns not leaking into business logic or data access
- Public API surface: internal details leaked through public types?
- Cross-cutting concerns (auth, logging, error handling) handled via middleware/traits, not duplicated per handler
- Dependency direction correct (high-level depends on abstractions, not vice versa)
- Empty directories or dead placeholder modules
- Frontend organization: components, stores, routes, API layer
- Consistent, typed pattern for API communication and error normalization across the frontend
- Global state (`$state`, stores) used appropriately vs passed as props
- Folder/file naming consistent and predictable
- Premature optimizations or over-engineered sections

## 8. Rust Code Quality & Idioms

- Error handling via `Result<T, E>` with meaningful error types (`thiserror`); informative errors, no swallowed errors
- `unwrap()`/`expect()`/`panic!` in production paths where graceful error return is appropriate
- Excessive or avoidable `clone()` calls; correct lifetimes, ownership, borrowing; unnecessary `Arc<Mutex<>>` wraps
- Async correctness: no blocking I/O or heavy computation without `spawn_blocking`
- Concurrency: race conditions on shared state, check-then-act sequences that are not atomic, lost updates under concurrent requests
- `unsafe` code justified and documented
- Axum extractors, `State<T>`, and middleware layers used correctly
- Dead code: `#[allow(dead_code)]`, unused imports, unreachable branches; TODO/FIXME in critical paths
- Passes `cargo clippy --workspace --all-targets -- -D warnings`; clippy configuration appropriate, no allowed lints that should be enforced

## 9. Frontend Code Quality & Svelte Idioms

- Svelte 5 rune syntax (`$state`, `$derived`, `$effect`, `$props`, `$bindable`) used correctly and consistently — no mixing of old and new APIs
- `$effect` blocks cleaned up properly to avoid memory leaks or stale subscriptions
- Reactive dependencies in `$derived`/`$effect` complete and accurate
- Component responsibility well-scoped (no god components); components small, focused, reusable
- API layer abstracted — no raw `fetch` calls scattered across components
- Loading, error, and empty states handled in all data-fetching paths
- Form validation on the frontend (not just backend)
- Custom routing (history API) robust; edge cases handled
- TypeScript used strictly; no `any` where typing would help
- Unhandled promise rejections in event handlers
- Accessibility: ARIA roles, keyboard navigation, focus management; suppressed a11y warnings that should be fixed instead of silenced
- Responsive design: does the UI work on mobile?
- CSS organization

## 10. Database & Data Layer

- Schema design: normalization, constraints, indexes, data types
- Migrations versioned, sequential, safe for existing data; rollback strategy
- Connection pooling configured correctly (pool size, timeouts, idle connections)
- Transactions used where multiple operations must be atomic
- N+1 query patterns; missing indexes on frequently queried or joined columns
- Error handling around database failures (retries where appropriate)
- Data validation enforced at both database level (constraints) and application level
- SQLite pragmas configured correctly (foreign_keys, WAL, busy_timeout, synchronous); adequate for expected concurrency; locking issues
- Cascade delete behavior (`ON DELETE`) intentional — no accidental data loss or orphaned rows
- SQLite backup and recovery strategy
- Time handling: timestamps stored consistently (UTC, single format); expiry and comparison logic correct across timezones and clock skew
- Data lifecycle: account/resource deletion removes or anonymizes associated data; no orphaned or unbounded-growth tables

## 11. API Design

- RESTful and consistent: resource naming, HTTP verbs, correct status codes (201 for creation, 204 for empty responses, not 200 for errors)
- Consistent error response format across all endpoints
- Pagination on collection endpoints — no unbounded list responses; implementation correct and efficient
- API versioning strategy (or documented plan)
- Request/response schemas documented; any generated artifacts (API spec, client) kept in sync with the actual code
- Endpoints exposing more data than necessary (over-fetching, sensitive field leakage)
- Content-Type and Accept header handling
- Idempotency and safe-retry behavior of mutating endpoints (double submission, duplicate resource creation)

## 12. Testing

- Coverage across unit, integration, and end-to-end levels; critical paths covered (auth flow, authorization, token refresh, OAuth, error cases)
- Tests verify actual behavior, not just that code runs — meaningful assertions
- Tests independent and idempotent; no shared mutable state; no flaky (timing- or order-dependent) tests
- Test infrastructure: does the test database/environment setup faithfully reflect production behavior? Test data management; hardcoded data that will cause future failures
- Error paths, boundary conditions, and race conditions tested, not just happy paths
- Frontend tests: unit, component, E2E (Playwright/Cypress)
- Test maintainability: shared setup logic, fragility

## 13. Error Handling & Resilience

- All error cases handled explicitly — no silently swallowed errors
- Errors surfaced to users usefully without leaking stack traces, internal paths, or DB errors
- Global error handler/fallback in the Axum router and the Svelte frontend
- Timeouts on external HTTP calls and database queries; retry with backoff for transient failures
- Potential infinite loops or unbounded resource consumption paths
- Graceful degradation when a dependency (DB, external service) is unavailable
- Graceful shutdown on SIGTERM

## 14. Logging & Observability

- Structured logging with appropriate log levels; correlation/request ID threaded through logs
- Logs free of sensitive data (PII, secrets, tokens, passwords)
- Security-relevant events audited: login, logout, token refresh, failed attempts, permission changes, data mutations
- Health check endpoints adequate for orchestration (`/health`, readiness)
- Application metrics exposed (request count, latency, error rate)
- Observability proportionate to the deployment scale — neither missing where needed nor over-engineered
- Unhandled errors captured and reported

## 15. Configuration & Environment

- Config layering (common → env-specific → local → env vars) correct and easy to understand
- Clear separation between development and production configuration; safe production defaults
- Required configuration validated at startup — fail fast on missing/invalid config
- All required environment variables and config keys documented

## 16. Containerization & Deployment

- Dockerfile: multi-stage build correctness, minimal base image, non-root user, image size
- `.dockerignore` excludes unnecessary files; layers ordered for optimal caching (dependencies before source)
- No hardcoded hostnames, ports, or paths that break across environments
- Docker Compose configuration suitable only for local development, not accidentally production
- Volumes, secrets, and network configuration appropriate
- Build reproducible from a clean state

## 17. CI/CD

- CI pipeline on every pull request: compilation, linting (clippy, ESLint/svelte-check), formatting (rustfmt, Prettier), tests
- Security scanning (`cargo audit`, `npm audit`, semgrep) in CI
- Drift between generated artifacts (API spec, client) and source detected in CI
- Git hooks consistent with CI checks; hooks are advisory only — CI must be the authoritative gate
- Build/automation scripts and task-runner code correct and maintainable (they are production-adjacent code)
- Pipeline fast enough to be useful (Cargo/npm dependency caching)
- Secrets managed in CI — not hardcoded in workflow files
- CD pipeline: deployment automation, rollback mechanism, versioning/release strategy

## 18. Documentation & Developer Experience

- README with setup instructions, architecture overview, how to run/test — sufficient for a new developer to get productive alone
- Public APIs and complex internal modules documented (Rust doc comments, JSDoc); non-obvious design decisions explained
- Local development setup straightforward: single command, clear prerequisites, repeatable across machines; hot reload / fast iteration
- Development environment reproducible from a clean clone (devcontainer or equivalent); no personal or machine-specific configuration baked in
- Tooling: linting, formatting, type-checking scripts; helpful error messages; adequate debug logging
- Build times: unnecessary rebuilds, incremental compilation working
- Meaningful commit messages; contribution guidelines or branching strategy

## 19. Performance & Scalability

- Blocking operations in hot paths; unnecessary allocations
- Unbounded memory growth (collections without limits)
- Caching used appropriately and invalidated correctly
- Heavy operations offloaded asynchronously
- Database queries optimized for expected data volumes
- Frontend: bundle size, lazy loading, unnecessary re-renders
- Asset serving: cache headers, compression, ETag usage
- Would the application handle a 10× traffic increase without architectural changes?

## 20. Business Logic Correctness

- Core domain invariants identified and actually enforced (in code and/or database constraints), not just assumed
- State transitions valid — no illegal state reachable through the API or through unusual request ordering
- Edge cases: empty collections, duplicates, unicode input, extreme or negative values, first/last elements
- Concurrent modification of the same resource handled deliberately (lost updates, double-submission)
- Behavior on partial failure: multi-step operations leave the system in a consistent state

## 21. General Code Hygiene

- Commented-out code that should be deleted; debug artifacts (`println!`, `console.log`, hardcoded test data)
- Files too large and in need of splitting; functions too long; god objects/modules
- Naming conventions consistent (variables, functions, types, files)
- Magic numbers and strings replaced with named constants or config
- Copy-pasted code that should be extracted into shared utilities
- All public interfaces intentional — no accidentally exposed internals
