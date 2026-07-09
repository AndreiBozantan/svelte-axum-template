# 17 — CI/CD

CI covers compile, lint, format, tests, and generated-artifact drift for both stacks, with
caching. The gaps: security scanning isn't gating, sqlx check is skipped in CI, and there's no
CD/release automation.

---

## 17.2 — `sqlx prepare --check` is skipped in CI

- **GitHub Issue:** [#253](https://github.com/AndreiBozantan/svelte-axum-template/issues/253)

- **Severity:** Minor
- **Location:** `xtask/checks.rs:245-257` (`ci_backend` comment: sqlx check "intentionally
  skipped in CI"), relies on clippy validating queries against `.sqlx/` under `SQLX_OFFLINE=true`.
- **Finding:** The reasoning (clippy + `SQLX_OFFLINE` validates queries against cached metadata,
  so stale/missing `.sqlx/` is caught) is mostly sound, but `sqlx prepare --check` also catches
  `.sqlx/` files that are stale relative to the _current_ queries in a way clippy may accept if the
  cached file still parses. The pre-push hook runs it locally, but hooks are advisory. So the
  authoritative gate (CI) is slightly weaker than local.
- **Recommendation:** Either run `sqlx prepare --check` in CI (it can run offline against the
  committed `.sqlx/` and a throwaway SQLite DB created in the job), or document clearly why clippy
  coverage is considered sufficient. Prefer making CI authoritative.

---

## 17.3 — No CD / release pipeline, versioning, or rollback automation

- **GitHub Issue:** [#255](https://github.com/AndreiBozantan/svelte-axum-template/issues/255)

- **Severity:** Important
- **Location:** `.github/workflows/` (only `ci.yml` and `semgrep.yml`); no release/publish/deploy
  workflow; no image publishing.
- **Finding:** There is no automation to build/publish the Docker image, tag releases, or deploy/
  rollback. `Cargo`/`package.json` versions (0.8.0) are maintained by hand. For a production SaaS
  template this is a notable omission (the review asks about CD, rollback, release strategy).
- **Recommendation:** Add a release workflow (tag → build + push the hardened image to a registry
  with the version tag), and document the rollback approach (redeploy previous tag). Keep the DB
  migration story (`app migrate run` / `deploy`) in that pipeline.

---

## 17.4 — CI ignores `*.md`/`docs/**` — fine, but note the branch trigger

- **Severity:** Minor
- **Location:** `.github/workflows/ci.yml:1-24`.
- **Finding:** CI runs on push/PR to `main` (with `workflow_dispatch`), cancels in-progress runs
  per ref, and skips doc-only changes. Reasonable. The comment "for manual-only mode: comment out
  push/pull_request" suggests the triggers are sometimes toggled off — make sure they're on for
  the protected branch. Permissions are correctly minimized (`contents: read`).
- **Recommendation:** Ensure branch protection requires the CI checks. Keep triggers enabled.

---

## 17.5 — Hooks mirror CI and are advisory; verified

- **Severity:** Informational
- **Location:** `xtask/checks.rs` (`pre_commit`, `pre_push`, `ci_backend`, `ci_frontend`).
- **Finding:** Pre-commit does fmt + spec drift; pre-push does lint + sqlx + tests + drift,
  selectively by changed paths, with a full-run fallback. CI runs the same underlying checks. Hooks
  are installed via `setup-hooks` and are advisory (CI is the gate), matching the stated intent.
  The selective-by-path logic is a nice touch. Good.
