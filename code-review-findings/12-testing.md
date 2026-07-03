# 12 — Testing

Test quality for the auth/token flows is genuinely good: reuse detection, grace-period
concurrency, tenant isolation, rehash-on-login, and expiry are all covered with meaningful
assertions against real (in-memory SQLite) behavior. The gaps are in breadth, not depth.

---

## 12.1 — No tests for authorization / data-isolation on `GET /api/users`

- **Severity:** Important
- **Location:** `backend/test/platform/identity/users_tests.rs` (covers auth-required and query
  validation, but not *who can see whom*).
- **Finding:** There is no test asserting that a normal user cannot enumerate other users, or
  that list results are correctly tenant-scoped from the API's perspective. Given the disclosure
  issue in [02](02-authorization-access-control.md), this is exactly the missing coverage that
  let it slip.
- **Recommendation:** Add tests: (a) two users in tenant 0 — user A lists and sees B (documents
  current behavior, which should then fail once authz is added); (b) after adding roles, a
  non-admin gets 403/404. Test the security boundary explicitly.

---

## 12.2 — OAuth callback flow is untested end-to-end
- **GitHub Issue:** [#249](https://github.com/AndreiBozantan/svelte-axum-template/issues/249)

- **Severity:** Important
- **Location:** `auth_tests.rs` (backend/platform/identity/auth) tests `login_oauth` at the
  service layer only; no test drives `google_auth_init` → cookie → `google_auth_callback`,
  CSRF match/mismatch, or PKCE. `oauth_service.rs` HTTP calls to Google aren't abstracted for
  faking.
- **Finding:** The service-level SSO tests are good, but the CSRF/state-cookie/PKCE machinery —
  the security-critical part — has no coverage because the Google token/userinfo HTTP calls
  aren't injectable. `validate_redirect_path` is well tested in isolation, but the callback's
  CSRF-mismatch and expired-state branches are not.
- **Recommendation:** Abstract the outbound Google calls behind a trait/injected client so the
  callback can be tested with a fake, and add CSRF-mismatch / expired-state / happy-path
  callback tests.

---

## 12.3 — Empty test module compiles but asserts nothing

- **Severity:** Minor
- **Location:** `backend/test/app/sample/sample_tests.rs` (empty), declared at
  `backend/main.rs:104-106`.
- **Finding:** An empty test file masquerades as coverage for the sample app. The review
  criteria: "An execution without an assert! is not a test" — here there isn't even an execution.
- **Recommendation:** Add a real test for the sample endpoint or remove the module.

---

## 12.4 — No frontend component/E2E tests; only the refresh manager is covered
- **GitHub Issue:** [#252](https://github.com/AndreiBozantan/svelte-axum-template/issues/252)

- **Severity:** Minor
- **Location:** `frontend/test/auth-refresh-manager.test.ts` (thorough, 437 lines),
  `frontend/test/dummy.test.ts` (placeholder).
- **Finding:** The refresh manager has excellent unit coverage (fake timers, coalescing, cross-
  tab). But there are no component tests (Login form, routing/redirect logic in `App.svelte`)
  and no E2E (Playwright/Cypress). Three shipped bugs would have been caught by basic component
  tests: the Login stuck-spinner-on-error (9.1), the `[object Object]` render in Logout (9.2),
  and the wrong `isAdmin` display (9.3) — see [09](09-frontend-code-quality.md).
- **Recommendation:** Add component tests (e.g. vitest + `@testing-library/svelte`) for Login —
  submit, error display re-enables the button, disabled-while-pending — and for the
  auth-redirect logic. Consider a minimal Playwright smoke test for
  login→protected-page→logout. Remove `dummy.test.ts`.

---

## 12.5 — Test infrastructure faithfully mirrors prod behavior; verified

- **Severity:** Informational
- **Location:** `backend/test/test_server.rs`, `common.rs:99-134` (`create_test_context`).
- **Finding:** Tests use the real router and real migrations against in-memory SQLite, with
  rate limiting disabled and shorter token lifetimes — a faithful, isolated setup. Tests are
  independent (fresh DB per server) and the concurrency test uses a barrier rather than sleeps.
  Good foundation. Note: in-memory SQLite (`sqlite::memory:`, `max_connections = 1`) doesn't
  exercise WAL/multi-connection locking that prod uses — acceptable, but be aware busy-timeout/
  lock behavior isn't tested.
