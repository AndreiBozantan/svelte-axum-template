# 11 — API Design

Consistent error envelope, good status-code discipline, and an auto-generated OpenAPI spec +
TS client kept in sync by CI. But there is a shipped path bug, a docs/code contract mismatch,
and the list endpoint violates the project's own pagination convention.

---

## 11.1 — `/api/api/sample` — duplicated path prefix ships in the spec and client

- **Severity:** Important
- **Location:** `backend/app/sample/sample_api.rs:18-24` (`#[utoipa::path(... path = "/api/sample")]`
  on a route already nested under `/api` in `router.rs:53`), resulting in `/api/api/sample` in
  `openapi.json` and `frontend/src/lib/generated/endpoints.ts:14-15`.
- **Finding:** Every other handler declares its path *without* the `/api` prefix (the router
  adds it via `.nest("/api", ...)`). The sample handler hardcodes `/api/sample`, so nesting
  produces the doubled `/api/api/sample`. The generated client exposes `api.sample.get_sample()`
  hitting `/api/api/sample`.
- **Risk:** Broken/confusing public route; sets a bad copy-paste template for new endpoints
  (this file is explicitly the "template" per AGENTS.md conventions).
- **Recommendation:** Change the sample handler's `path` to `/sample` (matching the others),
  regenerate the spec/client with `cargo xtask openapi`.

---

## 11.2 — `GET /api/users` uses offset pagination and returns `total`, contradicting `conventions.md`

- **Severity:** Minor
- **Location:** `backend/platform/identity/users/users_api.rs:36-92`,
  `docs/api/conventions.md:167-180` (mandates cursor pagination, "Offset pagination breaks
  under writes; don't use it").
- **Finding:** The only list endpoint uses `limit`/`offset` and returns `{ users, total, limit,
  offset }`, while the conventions doc explicitly says to use cursor pagination and wrap lists
  as `{ items, next_cursor }`. The response also uses `users:` not the documented `items:`.
  It's a template, but it models the *wrong* pattern for others to copy.
- **Risk:** Inconsistent list contract; `COUNT(*)` on every list call (see
  [19](19-performance-scalability.md)).
- **Recommendation:** Either update the endpoint to the documented cursor shape, or relax the
  convention doc to permit offset pagination for small/admin lists. Make code and docs agree.

---

## 11.3 — Error `code` strings don't match the documented contract

- **Severity:** Minor
- **Location:** `backend/platform/shared/api.rs:82-90` (`invalid_token`),
  `docs/api/conventions.md:85-92` (documents `not_authenticated` and `token_expired`).
- **Finding:** The conventions doc lists standard codes `not_authenticated` and `token_expired`,
  but the code emits `invalid_token` and `expired_token`. The frontend `main.ts:31` checks for
  `not_authenticated`, which the backend never sends — so that branch is dead. Three sources
  (docs, backend, frontend) disagree on the stable machine-readable identifiers that clients are
  told to branch on.
- **Risk:** The one thing the doc says is "part of the API contract" (stable `code` values) is
  inconsistent across the stack.
- **Recommendation:** Pick the canonical set, fix `api.rs` and the docs and the frontend check
  to match. Add a test asserting the `code` for the 401 cases.

---

## 11.4 — No `Retry-After` header on 429 despite documented convention

- **Severity:** Minor
- **Location:** `backend/platform/shared/rate_limiter.rs:79-81` (`custom_error_handler` returns
  a bare `too_many_requests()`), `conventions.md:24,92` (says `Retry-After` is set).
- **Finding:** The 429 response omits `Retry-After`, which the conventions promise. `tower_governor`
  can supply the wait duration; it's discarded here.
- **Recommendation:** Populate `Retry-After` from the governor error's wait time.

---

## 11.5 — No idempotency support for mutating endpoints

- **Severity:** Minor (acknowledged as deferred)
- **Location:** `conventions.md:193-197` (§10 marks idempotency keys as "not implemented today").
- **Finding:** Register/login/refresh are not idempotent and double-submission of register can
  produce a `409` (handled) but there's no idempotency-key mechanism. This is explicitly
  deferred in the docs, so it's a known gap, not an oversight.
- **Recommendation:** Fine to defer; keep the note. Ensure register's duplicate handling stays
  race-safe via the DB unique constraint (it is — `UniqueConstraintViolation` → 409).

---

## 11.6 — OpenAPI/codegen sync enforced in CI; verified

- **Severity:** Informational
- **Location:** `xtask/checks.rs:188-243` (`check_backend_openapi_drift`,
  `check_frontend_openapi_drift`), `.github/workflows/ci.yml`.
- **Finding:** Spec drift and generated-client drift are both checked in CI by regenerating and
  `git diff --exit-code`. Generated files are never hand-edited. This is a good setup and works.
  No change needed.
