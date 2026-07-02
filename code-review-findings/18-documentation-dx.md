# 18 — Documentation & Developer Experience

DX is a strength: devcontainer, `cargo xtask` for everything, single-command init, good
architecture docs (`AGENTS.md`, `conventions.md`, `codegen.md`). Findings are gaps and drift.

---

## 18.1 — Docs and code disagree in several places

- **Severity:** Important
- **Location:** `docs/api/conventions.md` vs code:
  - §5/§3 error codes `not_authenticated`/`token_expired` vs actual `invalid_token`/`expired_token`
    (see [11](11-api-design.md) 11.3).
  - §8 mandates cursor pagination; the users endpoint uses offset (11.2).
  - §9 says unknown request fields are rejected via `deny_unknown_fields`; DTOs don't set it
    (see [03](03-input-validation-injection.md) 3.3).
  - §2 shows list responses as `{ items, next_cursor }`; code returns `{ users, total, ... }`.
- **Finding:** The conventions doc reads as an aspirational spec, but it's presented as "the
  contract every backend endpoint follows." New contributors will trust it and be misled.
- **Recommendation:** Reconcile doc and code — either implement the conventions or mark the
  unimplemented parts clearly as "target, not yet enforced" (some sections already do this; make
  it consistent).

---

## 18.2 — Almost no doc comments on public APIs / complex modules

- **Severity:** Minor
- **Location:** `main.rs:5` (`#![allow(missing_docs)]`), most `pub fn`/`pub struct` across the
  backend.
- **Finding:** `missing_docs` is allowed and most public items have no `///` docs. A few complex
  areas are well-commented (the OAuth state-cookie rationale, the refresh-manager, the config
  layering), but the general public surface is undocumented. `missing_errors_doc` is also allowed.
- **Recommendation:** Add doc comments to the non-obvious public functions (auth/token/service
  APIs, error conversions) and to module heads. Consider removing `allow(missing_docs)` for the
  `platform::shared` public API at least.

---

## 18.3 — README is thin on architecture and testing

- **Severity:** Minor
- **Location:** `README.md`.
- **Finding:** The README covers running, config, migrations, and OAuth setup well, but doesn't
  explain the architecture (defers entirely to `AGENTS.md`), how to run tests
  (`cargo xtask ci-backend`/`ci-frontend` aren't mentioned), or the security model. A new
  developer would get the app running but not understand the auth flow or how to validate changes.
- **Recommendation:** Add a short architecture overview and a "running tests / checks" section to
  the README (or link `AGENTS.md` and the xtask help prominently).

---

## 18.4 — Stale/committed scratch artifacts in the working tree

- **Severity:** Minor
- **Location:** `tmp/` (git-ignored but present: many `tmp/code-review/*`, `tmp/plans/*`),
  `.pytest_cache/`, `.venv/` present in the tree; `project-review-prompt.md` / `project-todos.md`
  untracked at root.
- **Finding:** `tmp/` is git-ignored (good), but a `.venv/` and `.pytest_cache/` (Python) sit in a
  Rust/Svelte repo — leftover from tooling — and aren't in `.gitignore` (only `.env`, `target`,
  etc. are). Confirm they're not tracked. The root has stray untracked planning docs.
- **Recommendation:** Add `.venv/` and `.pytest_cache/` to `.gitignore` (or remove them), and move
  loose planning docs into `docs/` or delete. Housekeeping only.

---

## 18.5 — Devcontainer & xtask DX are excellent; verified

- **Severity:** Informational
- **Location:** `.devcontainer/`, `xtask/`, `README.md:11-29`.
- **Finding:** One-command `cargo xtask dev-init` / `dev`, devcontainer with toolchains + hooks +
  shell completion, and a self-documenting `xtask --help`. Reproducible from a clean clone. This is
  a genuinely good developer experience.
