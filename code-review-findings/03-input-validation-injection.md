# 03 — Input Validation & Injection

Strong here overall: all SQL is parameterized via `sqlx::query!`, the frontend renders no
`{@html}`, and email is normalized/validated. Findings are edge cases and DoS limits.

---

## 3.1 — No request body size limit; JSON payloads are unbounded
- **GitHub Issue:** [#198](https://github.com/AndreiBozantan/svelte-axum-template/issues/198)

- **Severity:** Important
- **Location:** `backend/router.rs:23-73` (no `DefaultBodyLimit` / body cap layer),
  `backend/platform/shared/api.rs:258-278` (`Json` extractor wraps `axum::Json`).
- **Finding:** Axum's `Json` extractor has a default 2MB limit *only* when the default body
  limit layer is present; the router applies `tower_http` trace and catch-panic layers but
  no explicit `DefaultBodyLimit`. More importantly, endpoints like register/login accept
  arbitrary-length `password`/`email`/`first_name`/`last_name` strings. Argon2 hashing an
  attacker-supplied multi-megabyte password is a CPU-amplification DoS.
- **Risk:** Memory/CPU DoS via large bodies and very long passwords (each hash is
  intentionally expensive; hashing huge inputs multiplies cost).
- **Recommendation:** Add an explicit `axum::extract::DefaultBodyLimit` (e.g. 64KB for the
  API) at the router level, and add a max-length validator to `password` (e.g. 8..=1024) and
  the name fields. `validator` already validates min length on password — add `max`.

---

## 3.2 — Register accepts unbounded/unvalidated `first_name` / `last_name`
- **GitHub Issue:** [#198](https://github.com/AndreiBozantan/svelte-axum-template/issues/198)

- **Severity:** Minor
- **Location:** `backend/platform/identity/auth/auth_api.rs:37-47` (`RegisterRequest`).
- **Finding:** `first_name`/`last_name` are `Option<String>` with no length or content
  validation. They are currently not returned by any endpoint, but they are stored and will
  eventually be displayed. No max length, no trimming, no unicode normalization.
- **Risk:** Storage bloat; future stored-XSS/display issues when these are surfaced.
- **Recommendation:** Add `#[validate(length(max = ...))]` and trim. Decide on a normalization
  policy now.

---

## 3.3 — Unknown fields in request bodies are silently accepted (contradicts documented convention)
- **GitHub Issue:** [#236](https://github.com/AndreiBozantan/svelte-axum-template/issues/236)

- **Severity:** Minor
- **Location:** `docs/api/conventions.md:188` states unknown fields are rejected via
  `serde(deny_unknown_fields)`; DTOs in `auth_api.rs`, `users_api.rs` do **not** set it.
- **Finding:** The documented contract says extra fields yield `400 validation_failed`, but
  no request DTO uses `#[serde(deny_unknown_fields)]`, so typos and unexpected fields are
  ignored.
- **Risk:** Client bugs (misspelled field names) pass silently; drift between docs and code.
- **Recommendation:** Add `#[serde(deny_unknown_fields)]` to request DTOs, or update the
  convention doc to match reality. Prefer enforcing it.

---

## 3.4 — Path-traversal handling in the static handler is safe; verified

- **Severity:** Informational
- **Location:** `backend/platform/shared/assets.rs:17-54`.
- **Finding:** `static_handler` looks assets up by key in the compiled `rust-embed` map
  (`Assets::get(path_str)`), which is not a filesystem read, so `../` traversal cannot
  escape to the host FS. The SPA fallback only serves `index.html`. This is correct. No
  change needed.

---

## 3.5 — `validate_redirect_path` is thorough; one small note

- **Severity:** Informational
- **Location:** `backend/platform/identity/oauth/oauth_service.rs:320-349`, tests in
  `backend/test/platform/identity/validate_redirect_path_tests.rs`.
- **Finding:** Open-redirect defense checks length, leading single slash, rejects `//`,
  control chars, `://`, backslashes, and enforces idempotent percent-decoding. Good coverage.
  It only guards against absolute/protocol-relative URLs; it does not restrict which internal
  paths are allowed, which is acceptable for an SPA. No change required.
