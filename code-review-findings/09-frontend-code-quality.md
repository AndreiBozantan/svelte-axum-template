# 09 — Frontend Code Quality & Svelte Idioms

Runes are used correctly and consistently, the API layer goes through the generated client
(with one exception), and the token-refresh manager is genuinely well engineered. But there
are three user-facing bugs and several correctness/idiom issues that should be fixed before
building app features on top of this template.

---

## 9.3 — `isAdmin` is derived from `user.id === 1`, which is not the admin

- **GitHub Issue:** [#223](https://github.com/AndreiBozantan/svelte-axum-template/issues/223)

- **Severity:** Important (incorrect privilege display)
- **Location:** `frontend/src/lib/AppState.svelte.ts:26`
  (`isAdmin = $derived(this.user !== null && this.user.id === 1)`); backend seeds the system
  admin as **user id 0** (`migrations/01_initial_schema.sql:52-53`), and id 1 is simply the
  first ordinary user to register (AUTOINCREMENT).
- **Finding:** The admin heuristic is wrong: it grants the "admin" UI (shield icon) to
  whichever normal user happens to get row id 1, and never to the actual seeded admin (id 0).
  There is also no backend authorization behind this (see [02](02-authorization-access-control.md)),
  so it is purely cosmetic today — but it is misleading and will become a real bug if any
  behavior is ever gated on it.
- **Recommendation:** Remove client-side admin inference entirely and derive it from a
  backend-provided `role`/`is_admin` field on `UserInfo` (added as part of 02.2). Never infer
  privilege from a database row id.

---

## 9.4 — Sidebar navigation does full page reloads; SPA routing only half-exists

- **GitHub Issue:** [#205](https://github.com/AndreiBozantan/svelte-axum-template/issues/205)

- **Severity:** Important (architecture; the template's routing pattern is what apps will copy)
- **Location:** `frontend/src/AppSidebar.svelte:121-150` (`<a href={getPagePath(item.id)}>`
  with no click handler), `frontend/src/App.svelte:10-55`, `frontend/src/AppPages.svelte.ts`.
- **Finding:** The nav links are plain `<a>` elements without `preventDefault`/`pushState`,
  so every sidebar click triggers a **full browser navigation**: the server re-serves
  `index.html`, the bundle re-executes, `bootstrap()` re-fetches `/api/users/me`, and all
  client state is discarded. The SPA machinery that does exist (`history.pushState` +
  `popstate` listener + the redirect `$effect`) is only exercised by the logout button and
  auth redirects — the `popstate` handling is effectively dead for normal navigation because
  each click starts a fresh document. Related issues: (a) the path→page parsing is duplicated
  between `onMount` and the `popstate` listener; (b) the `popstate` listener is added in
  `onMount` without cleanup (harmless for the root component, but a bad pattern to copy);
  (c) an unknown path renders a "Page Not Found" branch keyed off the raw path slice rather
  than a real 404 route; (d) `svelte-spa-router` is a dependency (`package.json:41`) but
  is never imported; (e) the redirect `$effect` performs imperative navigation
  (`history.pushState`) inside an effect, which the review criteria flag as a last resort.
- **Risk:** Every navigation pays a reload + an extra auth round-trip; in-memory state
  (e.g. a half-filled form) is lost; apps built on the template inherit a routing pattern
  that looks like SPA routing but isn't.
- **Recommendation:** Decide the routing story once: either adopt the already-installed
  `svelte-spa-router` (and delete the hand-rolled logic), or finish the custom approach —
  intercept nav clicks (`onclick` with `preventDefault` + `pushState` + `setActivePage`),
  extract one shared `pathToPage()` used by both `onMount` and `popstate`, and add a real
  404 page entry. Remove the unused router dependency if the custom approach stays.

---

## 9.5 — `About.svelte` calls the API with raw `fetch`, bypassing the generated client

- **GitHub Issue:** [#242](https://github.com/AndreiBozantan/svelte-axum-template/issues/242)

- **Severity:** Important (project-standards breach in template code)
- **Location:** `frontend/src/pages/About.svelte:9` (`await fetch('/api/health')`);
  the generated client already exposes this endpoint
  (`api.health.health_check`, `frontend/src/lib/generated/endpoints.ts:46-54`).
- **Finding:** AGENTS.md and the review criteria mandate that all backend calls go through
  the generated client; raw `fetch()` is only allowed inside `lib/fetch.ts`. `About.svelte`
  hand-rolls the health call, skipping the client's error-normalization and auth middleware.
  As template code, this is exactly the example a new contributor will copy.
- **Recommendation:** Replace with `api.health.health_check()` and derive the three states
  (`Operational` / `Service issues` / `Offline`) from `data`/`error`. The `NETWORK_ERROR`
  normalization in `fetch.ts` (see 9.7) currently makes "offline" indistinguishable from a
  500 through the client — fixing that finding makes this one clean.

---

## 9.6 — `PageDefinition.component` typed as `any`

- **GitHub Issue:** [#244](https://github.com/AndreiBozantan/svelte-axum-template/issues/244)

- **Severity:** Minor
- **Location:** `frontend/src/AppPages.svelte.ts:23` (`component: any`);
  generated `endpoints.ts` uses `as any` on every call (generated file — out of scope to
  hand-edit, noted in [11](11-api-design.md)).
- **Finding:** `tsconfig` is `strict`, but `component: any` defeats type-checking for the page
  registry. The hand-written `any` is fixable.
- **Recommendation:** Type `component` as `Component` (Svelte 5's component type from
  `svelte`) instead of `any`.

---

## 9.7 — `fetch.ts` `onError` middleware swallows the real error and always returns 500

- **GitHub Issue:** [#243](https://github.com/AndreiBozantan/svelte-axum-template/issues/243)

- **Severity:** Minor
- **Location:** `frontend/src/lib/fetch.ts:10-23`.
- **Finding:** Network/abort errors are converted into a synthetic `500` response with code
  `NETWORK_ERROR`. That is a reasonable normalization, but: (a) an aborted request or offline
  state is indistinguishable from a server 500, so the UI can't message appropriately (see
  9.5); (b) the original error is discarded without even a dev log; (c) the code string is
  `SCREAMING_CASE` while every backend error code is `snake_case` (`invalid_token`,
  `validation_error`) — consumers matching on codes now face two conventions.
- **Recommendation:** Log the underlying error (at least behind `import.meta.env.DEV`), use a
  distinct status/code for network failure (e.g. `503` + `network_error` in snake_case), and
  document the synthetic shape next to the middleware.

---

## 9.8 — Frontend expects error code `not_authenticated`, backend never emits it

- **GitHub Issue:** [#224](https://github.com/AndreiBozantan/svelte-axum-template/issues/224)

- **Severity:** Minor
- **Location:** `frontend/src/main.ts:31` (`error.code !== 'not_authenticated'`); backend
  emits `invalid_token`/`expired_token` (`backend/platform/shared/api.rs`).
- **Finding:** The "expected 401" special-case in `bootstrap()` never matches, so every
  ordinary auth failure is `console.warn`-ed as unexpected. The frontend follows
  `docs/api/conventions.md:86`, the backend doesn't — a doc/code mismatch, see
  [11](11-api-design.md) 11.3 and [18](18-documentation-dx.md) 18.1.
- **Recommendation:** Align on one set of codes (either implement `not_authenticated` in the
  backend per the conventions doc, or match `invalid_token`/`expired_token` here) and fix the
  doc in the same change.

---

## 9.9 — Logout confirmation is mouse-only, and keyboard users bypass it entirely

- **GitHub Issue:** [#246](https://github.com/AndreiBozantan/svelte-axum-template/issues/246)

- **Severity:** Minor (accessibility / UX consistency)
- **Location:** `frontend/src/AppSidebar.svelte:59-94` (global `mousemove`/`click` effect),
  `:153-184` (popup markup with `svelte-ignore a11y_mouse_events_have_key_events`),
  `:46-57` (`handleLogoutSidebarClick`).
- **Finding:** The logout confirm popup opens on `mouseenter` and closes based on global
  mouse position, with the a11y warning suppressed. The result is two inconsistent flows:
  a mouse user gets the popup and must click its "Logout" button, while a keyboard user
  (focus + Enter, popup never opened) triggers `handleLogoutSidebarClick`'s else-branch and
  is logged out immediately with **no confirmation at all**. There is also no Escape-to-close
  or focus management, and the "close when mouse moves above/right of the popup" heuristic is
  fragile.
- **Recommendation:** Make the confirmation state click-toggled rather than hover-driven so
  both input methods share one flow; close on Escape and on focus leaving the popup; remove
  the `svelte-ignore`. Also mark or wire up the non-functional Settings toggles
  (`Settings.svelte:29-55`) so template users don't assume they persist.

---

## 9.11 — State/runes usage is correct; verified

- **GitHub Issue:** [#247](https://github.com/AndreiBozantan/svelte-axum-template/issues/247)

- **Severity:** Informational
- **Location:** `frontend/src/lib/AppState.svelte.ts`, page components.
- **Finding:** Global state is a single rune-based class instance with small setters (matches
  the documented pattern), `$derived` is used for computed values (not `$effect`), and the
  popup-listener effect returns a proper cleanup function (`AppSidebar.svelte:88-93`). No
  legacy `$:` or `svelte/store`. Optional values are checked null-safely
  (`AppState.user?.email`). The `AuthRefreshManager` (coalesced refresh, cross-tab Web Locks,
  jittered proactive timers, injectable `fetch`) is the strongest piece of frontend code and
  is thoroughly unit-tested. Good foundation to build on once 9.1–9.5 are fixed.
