# 06 — Dependency & Supply Chain

Lockfiles are committed and audits are currently clean. Gaps are process-level: no automated
scanning in CI and no update automation.

---

## 6.3 — Loose semver ranges on all dependencies

- **Severity:** Minor
- **Location:** `backend/Cargo.toml:11-48`, `frontend/package.json:21-45`.
- **Finding:** All deps use caret ranges (`"0.8"`, `"^7.0.0"`). This is idiomatic and fine
  _because_ `Cargo.lock` and `package-lock.json` are committed (verified), so builds are
  reproducible. Flagging only to confirm the lockfile-pinning is the thing keeping this safe —
  do not switch to `--no-lockfile` style installs anywhere.
- **Recommendation:** Keep lockfiles committed; ensure `npm ci` (used in Dockerfile/CI) not
  `npm install` in reproducible contexts. Dockerfile uses `npm ci` — good.

---

## 6.4 — Dev vs prod dependency separation is correct; verified

- **Severity:** Informational
- **Location:** `backend/Cargo.toml:54-55` (`axum-test` under `[dev-dependencies]`),
  `frontend/package.json` (build/test tooling under `devDependencies`).
- **Finding:** Test-only crates and frontend tooling are correctly segregated from runtime
  deps. The `scratch` runtime image ships only the compiled binary. No change needed.

---

## 6.5 — License compliance not tracked

- **GitHub Issue:** [#254](https://github.com/AndreiBozantan/svelte-axum-template/issues/254)

- **Severity:** Minor
- **Finding:** No license allow-list is enforced (e.g. `cargo deny check licenses`). For a
  template that others will build products on, an accidental copyleft transitive dep would go
  unnoticed.
- **Recommendation:** Add `cargo deny check licenses` with an allow-list to the CI job from 6.1.
