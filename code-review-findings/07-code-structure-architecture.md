# 07 — Code Structure & Architecture

The DDD bounded-context layout is clean and consistent, the single `main.rs` module tree is a
reasonable (if non-idiomatic) choice, and layering (api / service / db) is mostly respected.
Findings are about a couple of leaks and premature structure.

---

## 7.1 — HTTP concerns leak into the domain/service layer

- **Severity:** Minor
- **Location:** `backend/platform/identity/auth/auth_service.rs:50-51`
  (`Error::InvalidHeaderValue(#[from] axum::http::header::InvalidHeaderValue)`).
- **Finding:** The auth *service* error enum carries an Axum HTTP header error variant. The
  service layer (business logic) should not know about HTTP header types; that is a transport
  concern. It is a small leak but it is exactly the kind the review criteria call out
  ("HTTP concerns not leaking into business logic").
- **Recommendation:** Move header/cookie construction fully into the api layer and drop the
  HTTP variant from the service error. The service should return domain errors only.

---

## 7.2 — `users::Service` and `auth::Service` both hold a `db::Repository`, but services also expose `context.db`

- **Severity:** Minor
- **Location:** `backend/platform/identity/users/users_service.rs:106-119` (`pub users`,
  `pub context`), `auth_service.rs:84-99`.
- **Finding:** Repositories are injected (good), but every call site passes `&self.context.db`
  into repo methods (`self.users.find_by_id(&self.context.db, ...)`). The repository is a
  zero-field unit struct (`Repository;`) and the pool is reached through the context, so the
  "dependency injection" is partly ceremonial — the DB handle is ambient via context, not
  owned by the repo. Additionally `Service.context` and `Service.users` are both `pub`,
  exposing internals.
- **Risk:** Low; mostly a clarity/encapsulation point. It makes it easy to bypass the repo and
  hit `context.db` directly (and some handlers do: `service.users.list_by_tenant(&service.context.db, ...)`
  from the api layer, reaching through two layers).
- **Recommendation:** Either have the repository own the pool (constructed with it) so the DB
  handle isn't threaded through every call, or keep the current pattern but make fields
  non-`pub` and expose intent-revealing methods on `Service`. Avoid api-layer code reaching
  `service.users.<repo method>(service.context.db, ...)`.

---

## 7.3 — `xtask` is a single 388-line `xtask.rs` plus modules; mixed responsibilities

- **Severity:** Minor
- **Location:** `xtask/xtask.rs` (command dispatch + `dev`/`release`/`clean` logic inline),
  `xtask/{checks,database,docker,status,stop}.rs`.
- **Finding:** Most subcommands are factored into modules, but `dev`, `release`, `clean`,
  `dev_init`, and process monitoring live inline in `xtask.rs`. The `dev()` fn in particular
  is long and does port-waiting, spawning, and signal handling. This is build tooling, so the
  bar is lower, but it's production-adjacent per the review criteria.
- **Recommendation:** Extract `dev`/`release`/`clean` into their own modules to match the rest.
  Low priority.

---

## 7.4 — Empty/placeholder artifacts

- **Severity:** Minor
- **Location:** `backend/test/app/sample/sample_tests.rs` (empty file, 1 blank line);
  `data/test-data.sql` (empty); `backend/app/sample/sample_api.rs` (demo endpoint).
- **Finding:** `sample_tests.rs` is an empty file that is still declared as a module
  (`main.rs:104-106`) — it compiles but asserts nothing. `test-data.sql` is empty yet the
  migration runner reads and executes it in dev/test (harmless no-op, but confusing). The
  `sample` app endpoint is a template placeholder.
- **Recommendation:** Either put a real test in `sample_tests.rs` or remove the module
  declaration; document that `sample`/`test-data.sql` are intentional template scaffolding.

---

## 7.5 — Workspace split (backend + xtask) earns its complexity; verified

- **Severity:** Informational
- **Location:** root `Cargo.toml`, `xtask/Cargo.toml` (zero deps).
- **Finding:** Two-member workspace with `xtask` having no dependencies keeps automation
  builds near-instant and avoids polluting the app binary. The unified single-binary backend
  (one `main.rs` module tree, tests inside the crate to keep binary count at 1) is a
  deliberate, documented choice. This is reasonable; no restructuring needed.
