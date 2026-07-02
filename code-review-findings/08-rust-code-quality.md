# 08 — Rust Code Quality & Idioms

Idiomatic, clippy-clean (`--workspace --all-targets --all-features -D warnings` passes),
strong error-type discipline via `thiserror`, and `unwrap_used`/`expect_used` are denied at
the crate root. Findings are localized.

---

## 8.1 — `map_err` used where `From` conversions are the project standard

- **Severity:** Minor (project-standard breach per `AGENTS.md` / review-backend §1)
- **Location:** `backend/cli.rs:111-113,142-144,182-184` (`map_err(|e| Error::MigrationRunFailed { source: e })`),
  `backend/router.rs:123-126`, `backend/platform/shared/migrations.rs:56-57,75-76,88-92`.
- **Finding:** `AGENTS.md` and the backend review criteria say "avoid `map_err`, use error
  conversions instead." Several spots still use `map_err` where a `#[from]` conversion would
  let `?` do the work. Some are unavoidable (adding log context, mapping to a specific variant),
  but the migration ones are mechanical wrapping that `#[from]` could handle.
- **Recommendation:** Where the mapping only wraps a source error, add `#[from]` and use `?`.
  Keep `map_err` only where you genuinely add context or branch.

---

## 8.2 — Two production panics behind `const` / config paths

- **Severity:** Minor
- **Location:** `backend/platform/shared/crypto.rs:13-16`
  (`argon2::Params::new(...)` unwrapped in a `const` with `panic!` on error) and
  `backend/platform/shared/rate_limiter.rs:70-71`
  (`GovernorConfigBuilder::...finish().unwrap_or_else(|| unreachable!())`).
- **Finding:** The crate denies `unwrap_used`/`expect_used`, and these use `panic!`/
  `unreachable!` instead. The Argon2 params are compile-time constants so the panic can only
  fire if someone edits them to invalid values — acceptable, but it is a runtime panic in a
  `const` initializer path. The rate-limiter `unreachable!` fires at startup if
  `period`/`burst` are zero — but the guard at `:59` already returns early on zero values, so
  it is currently unreachable. Both are defensible; flagging for awareness since they are the
  only panics outside the deliberate `healthy_panic` test hook.
- **Recommendation:** Add a comment on the Argon2 `const` explaining the params are validated
  at compile time. For the rate limiter, consider surfacing a config error at startup instead
  of `unreachable!` in case the early guard is ever changed.

---

## 8.3 — `#[allow(dead_code)]` on DB row structs and several domain fields

- **Severity:** Minor
- **Location:** `backend/platform/identity/users/users_db.rs:20` (`Row`),
  `tokens/tokens_db.rs:9` (`Row`), `users_service.rs:16,36,77` (`User`, `CreateUserCommand`,
  `UserSsoInfo`), `users_db.rs:168` (`find_sso_info_by_id`).
- **Finding:** Multiple `#[allow(dead_code)]` annotations mask fields/methods that are read
  only in tests or reserved for future use (`first_name`/`middle_name`/`last_name`,
  `find_sso_info_by_id`). This is a legitimate pattern for full-table projections, but it
  accumulates and hides genuinely-unused code.
- **Recommendation:** For fields that are truly future-use, keep the allow but add a one-line
  comment (some already have this). For `find_sso_info_by_id` (only used in tests), gate it
  `#[cfg(test)]` or move it to the test module rather than `allow(dead_code)` in production.

---

## 8.4 — `Row` → domain conversions clone the whole row for the auth record

- **Severity:** Minor (performance/style)
- **Location:** `backend/platform/identity/users/users_db.rs:76-86`
  (`UserAuthRecord::try_from` does `row.clone().try_into()`).
- **Finding:** Building a `UserAuthRecord` clones the entire `Row` (to also build the nested
  `User`) rather than moving fields out. Not hot-path-critical (one row per login) but it is an
  avoidable clone that the review criteria specifically ask about.
- **Recommendation:** Destructure `Row` once and move the fields into both `User` and
  `UserAuthRecord` without cloning.

---

## 8.5 — `#[allow(clippy::unit_arg)]` / `unnecessary_wraps` / `unused_async` sprinkled

- **Severity:** Minor
- **Location:** `backend/cli.rs:76`, `backend/cli.rs:117`, `backend/router.rs:107`,
  `backend/app/sample/sample_api.rs:17`, `assets.rs:17,84`.
- **Finding:** A handful of targeted clippy allows. Most are legitimate (async handler
  signatures required by Axum, unit-arg from `match` arms). The review criteria ask that
  allowed lints be justified. They are individually reasonable but under-commented.
- **Recommendation:** Add a short `// reason:` note on each non-obvious allow, or drop the ones
  no longer needed. Low priority.

---

## 8.6 — Async/blocking review: clean; verified

- **Severity:** Informational
- **Finding:** Argon2 hashing (CPU-heavy) runs inline in async handlers rather than
  `spawn_blocking` — see [19 Performance](19-performance-scalability.md) 19.1 for that. No
  Mutex-across-await, no blocking file I/O in request paths (the JWT secret file is read once
  at startup, not per request), and `std::thread::sleep` appears only in `xtask` tooling. The
  background cleanup tasks use `tokio::time::interval` correctly with `MissedTickBehavior::Skip`.
