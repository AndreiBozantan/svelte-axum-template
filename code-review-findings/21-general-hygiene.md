# 21 — General Code Hygiene

The codebase is clean overall: consistent naming, no `println!`-debugging in backend request
paths, constants extracted, clippy-clean. Findings are small.

---

## 21.1 — `console.log`/`console.error` left in frontend production code

- **Severity:** Minor
- **Location:** `frontend/src/lib/auth-refresh-manager.ts:61,68,187,207,209` (`console.error`/
  `console.warn`/`console.log` incl. `"Proactively refreshing access token..."`),
  `frontend/src/main.ts:31,52`.
- **Finding:** Several `console.*` calls ship in production, including an informational
  `console.log` on every proactive refresh. Not harmful, but noisy and leaks internal behavior to
  the browser console.
- **Recommendation:** Gate debug logs behind `import.meta.env.DEV`, or route through a small logger
  that no-ops in production. Keep genuine error logging.

---

## 21.2 — Commented-out code blocks

- **Severity:** Minor
- **Location:** `frontend/src/App.svelte:11` (`// await new Promise(... setTimeout ... 900)`),
  `frontend/src/pages/Settings.svelte:82-105` (large commented-out CSS/button block),
  `frontend/src/lib/common.rs` n/a; `backend/platform/shared/common.rs:8` (`// pub type AppContext
  = ...`).
- **Finding:** Dead commented-out code in a few spots (an artificial loading delay, a big CSS
  comment block, a commented type alias). Review criteria: delete commented-out code.
- **Recommendation:** Remove them; git history preserves anything needed.

---

## 21.3 — `AppState.userId` field is unused / dead

- **Severity:** Minor
- **Location:** `frontend/src/lib/AppState.svelte.ts:24` (`userId = $state<number>(-1)`).
- **Finding:** `userId` is declared and initialized but never read or set anywhere (the app uses
  `user.id`). Dead state.
- **Recommendation:** Remove it.

---

## 21.4 — Inconsistent import style vs the documented convention

- **Severity:** Minor
- **Location:** `AGENTS.md` ("imports: `use module;` then qualify `module::MyType`; avoid
  `use module::MyType`") vs e.g. `backend/platform/shared/jwt.rs:4-12`, `config.rs:5-8`,
  `assets.rs:1-9` which `use` concrete types directly (`use chrono::DateTime;`,
  `use config::File;`, `use axum::http::header;`).
- **Finding:** The project convention is module-qualified imports, but many files import concrete
  types/functions directly. It's applied inconsistently (some files follow it, some don't).
- **Recommendation:** Pick one and enforce it (a lint/rustfmt setting won't catch this, so it's a
  review-discipline item). If the convention is real, sweep the violators; if not, relax the doc.

---

## 21.5 — Minor naming/label inconsistencies

- **Severity:** Minor
- **Location:** frontend package name `svelte-axum-project` (`package.json:2`) vs project name
  `svelaxum`; `docs/api/conventions.md:129-131` shows OAuth paths as `/api/auth/oauth/google` but
  the actual routes are `/api/oauth/google` (`oauth_api.rs`).
- **Finding:** Small naming drifts: the npm package name doesn't match the project, and the
  conventions doc's example OAuth paths don't match the implemented routes.
- **Recommendation:** Align names/paths. Trivial, but this is the "template" others copy.

---

## 21.6 — No file is oversized or a god-object; verified

- **Severity:** Informational
- **Finding:** Largest source files are `AppSidebar.svelte` (~600 lines, mostly CSS) and
  `auth_service.rs` (~390). Functions are generally small and focused; no god modules. Naming is
  consistent (snake_case Rust, the `_api/_db/_service` DDD triplet, PascalCase Svelte). Good
  hygiene overall.
