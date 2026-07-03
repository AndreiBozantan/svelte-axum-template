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

---

## 18.6 — Formatting is tooled and CI-gated, but lint-level style rules are not

- **Severity:** Minor
- **Location:** Present and enforced: `.editorconfig`, `rustfmt.toml`, `frontend/.prettierrc`
  (fmt checks run in the git hooks and in CI via `cargo xtask ci-backend` / `ci-frontend`).
  Missing: no ESLint config anywhere in `frontend/`; no `[workspace.lints]` section in the
  root `Cargo.toml`.
- **Finding:** Whitespace/formatting is fully enforced through tooling. But style rules
  *above* formatting are not: the frontend has no linter at all (prettier formats and
  `svelte-check` type-checks, but nothing catches unused variables, import ordering, `any`
  leakage, or Svelte a11y template issues), and the backend runs clippy with its default lint
  set only — there is no central `[workspace.lints.rust]`/`[workspace.lints.clippy]` table
  encoding the project's style choices. Conventions like import style
  ([21 § 21.4](21-general-hygiene.md#214--inconsistent-import-style-vs-the-documented-convention)) exist only as `AGENTS.md` prose that no tool checks.
- **Risk:** Style rules that only live in docs are applied inconsistently (21.4 is the
  evidence) and burn review time on nits a tool should catch, for humans and AI agents alike.
- **Recommendation:** (a) Add ESLint with `typescript-eslint` and `eslint-plugin-svelte`
  (flat config), wire it into the pre-commit hook and `cargo xtask ci-frontend`.
  (b) Add a `[workspace.lints.rust]` / `[workspace.lints.clippy]` table to the root
  `Cargo.toml` with the project's chosen lints, and have crates inherit via
  `lints.workspace = true`. (c) Keep `.editorconfig`/`.prettierrc`/`rustfmt.toml` agreeing on
  indent/width (they currently do: 4-space). Principle: every style convention is either
  encoded as a tool rule or deleted from the docs.

---

## 18.7 — Devcontainer bakes one developer's personal setup into the shared config

- **Severity:** Minor
- **Location:** `.devcontainer/setup-env.sh` (~260 lines writing a personal fish config,
  prompt, and abbreviations such as `cld` → `claude`), `.devcontainer/devcontainer.json`
  (personal named volumes: `svelaxum-gemini`, `svelaxum-fish-history`, `svelaxum-config`),
  `.devcontainer/statusline-command.sh`.
- **Finding:** The committed devcontainer mixes the generic project environment (toolchains,
  git hooks, build caches) with one maintainer's personal environment: fish shell config and
  prompt, Claude/Gemini CLI setup, and per-tool persistence volumes. A new contributor gets
  someone else's shell aliases and mounts by default, and personal-preference changes churn
  shared, reviewed files.
- **Risk:** Low — but as a template repo, the devcontainer is part of the product; personal
  coupling undermines the "clone and go" story for other people.
- **Recommendation:** Split generic from personal. Keep toolchains, hooks, caches, and
  completions in the shared config; move personal setup into clearly-named opt-in scripts
  (`setup-fish.sh`, `setup-gemini.sh`, `setup-claude.sh`, invoked from a git-ignored
  `setup-personal.sh` hook if present). Decide the volume strategy per tool (personal-tool
  volumes belong with the opt-in scripts). Optionally add variants (`setup-zsh.sh`) to prove
  the split works. Acceptance: a fresh clone with no personal scripts produces a working,
  neutral container.

---

## 18.8 — No guide/skill for scaffolding a new feature from a DB schema

- **Severity:** Minor
- **Location:** `.agents/skills/` (contains only `review-backend`, `review-frontend`,
  `triage-review-finding`); `AGENTS.md` names `backend/platform/identity/users/` as the
  template to copy.
- **Finding:** The most common extension task for this template — adding a new domain feature
  (migration → `_db`/`_service`/`_api` triplet → module declarations in `main.rs` →
  authorization wiring → utoipa annotations → `cargo xtask openapi` → frontend page → tests) —
  is documented only implicitly, by reading existing code. Every human or AI agent re-derives
  the sequence, and steps get skipped (codegen, test placement, authz guards).
- **Risk:** Inconsistent features and missed steps; the template's main value proposition
  (fast, correct feature scaffolding) stays tribal knowledge.
- **Recommendation:** Add a `create-feature` skill to `.agents/skills/` that takes an entity
  description / DB schema and walks the full checklist end to end, referencing the
  projects/tasks reference feature as the exemplar. Write it *after* that reference feature
  lands (Stage B of the [stabilization plan](stabilization-plan.md)) so it points at real,
  reviewed code rather than the `sample` placeholder.
