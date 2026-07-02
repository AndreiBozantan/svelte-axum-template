# 09 — Frontend Code Quality & Svelte Idioms

Runes are used correctly and consistently, the API layer goes through the generated client,
and the token-refresh manager is genuinely well engineered. But there are two user-facing
bugs and several correctness/idiom issues.

---

## 9.1 — `Logout.svelte` renders the whole user object instead of the email

- **Severity:** Important (visible bug)
- **Location:** `frontend/src/pages/Logout.svelte:15-17`.
- **Finding:** `You are still logged in as {AppState.user}.` interpolates the `UserInfo`
  object, which renders as `[object Object]`. Should be `{AppState.user?.email}`. Also, this
  branch is nearly unreachable because `onMount` logs out immediately, but if logout fails the
  user sees the broken string.
- **Recommendation:** Use `{AppState.user?.email}`. Consider showing a logout error state if
  `api.auth.logout()` fails (currently the result is ignored).

---

## 9.2 — `isAdmin` is derived from `user.id === 1`, which is not the admin

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

## 9.3 — Custom routing lives in `App.svelte` `$effect` and duplicates logic; edge cases

- **Severity:** Minor
- **Location:** `frontend/src/App.svelte:10-55`, `frontend/src/AppPages.svelte.ts`.
- **Finding:** Routing is hand-rolled: `onMount` parses `location.pathname`, a `popstate`
  listener re-parses, and a redirect `$effect` handles auth gating. Issues: (a) the
  `popstate`/`onMount` path-parsing logic is duplicated; (b) an unknown path becomes an
  `activePage` id that renders the "Page Not Found" branch rather than a real 404 route;
  (c) `svelte-spa-router` is a dependency (`package.json:41`) but appears unused — the app
  rolls its own routing instead. The redirect effect also runs business logic (history
  manipulation) inside an `$effect`, which the review criteria flag as a last resort.
- **Recommendation:** Either adopt the already-installed `svelte-spa-router` or extract the
  path→page mapping into one shared function and cover unknown-path handling. Remove the unused
  router dep if you keep the custom approach. Move imperative navigation out of `$effect` where
  practical.

---

## 9.4 — `PageDefinition.component` and other spots typed as `any`

- **Severity:** Minor
- **Location:** `frontend/src/AppPages.svelte.ts:23` (`component: any`),
  `frontend/src/lib/fetch.ts:14-24` (`onError` returns a `Response` but the middleware body is
  loosely typed; generated client calls cast `as any`).
- **Finding:** `tsconfig` is `strict`, but `component: any` defeats type-checking for the page
  registry, and the generated `endpoints.ts` uses `as any` on every call (that file is
  generated, so it is out of scope to hand-edit — noted in [11](11-api-design.md)). The
  hand-written `any` in `AppPages` is fixable.
- **Recommendation:** Type `component` as `Component` (Svelte 5's component type) instead of
  `any`.

---

## 9.5 — `fetch.ts` `onError` middleware swallows the real error and always returns 500

- **Severity:** Minor
- **Location:** `frontend/src/lib/fetch.ts:10-23`.
- **Finding:** Network/abort errors are converted into a synthetic `500` `NETWORK_ERROR`
  response. That is a reasonable normalization, but it means a genuinely aborted request or
  offline state is indistinguishable from a server 500, and the original error is discarded
  (not even logged). Combined with the auth middleware, a network blip on a GET could trigger
  a spurious refresh attempt.
- **Recommendation:** Log the underlying error (at least in dev) and consider a distinct
  `code`/status for offline vs server error so the UI can message appropriately.

---

## 9.6 — `Welcome.svelte`/`AppSidebar.svelte` read `AppState.user?.email` with non-null-safe assumptions elsewhere

- **Severity:** Minor
- **Location:** `frontend/src/pages/Welcome.svelte:11`, `AppSidebar.svelte:175`.
- **Finding:** These correctly use optional chaining. The review criterion about "`!== null`
  vs truthiness for API optionals" is generally respected. One spot to watch:
  `main.ts:31` branches on `error.code !== 'not_authenticated'`, but the backend never emits
  that code for the users endpoint (it emits `invalid_token`/`expired_token`, see
  `api.rs`). So the "expected 401" special-case never matches and every auth failure is
  `console.warn`-ed. Minor, but it's a code-string mismatch between front and back.
- **Recommendation:** Align the frontend's expected error `code` with what the backend actually
  returns (`invalid_token`/`expired_token`), or standardize the backend on `not_authenticated`
  per `conventions.md:86`. The docs and code disagree here — see [11](11-api-design.md).

---

## 9.7 — Accessibility & responsive: mostly fine, some gaps

- **Severity:** Minor
- **Location:** `frontend/src/AppSidebar.svelte:99-116,164-170` (a11y-ignored mouse handlers;
  logo `role="presentation"` with hover-only animation), `frontend/src/pages/Settings.svelte`
  (dummy toggles with no persistence).
- **Finding:** Interactive elements are real `<button>`/`<a>` (good). One suppressed a11y
  warning (`a11y_mouse_events_have_key_events`) hides a real gap: the logout confirm popup is
  driven by `mousemove`/`click` with no keyboard path. The Settings page toggles are
  non-functional placeholders. Mobile layout is handled via media queries (reasonable).
- **Recommendation:** Give the logout confirmation a keyboard-accessible path (Escape to close,
  focus management) instead of suppressing the warning. Mark the Settings toggles as
  non-functional or wire them up.

---

## 9.8 — State/runes usage is correct; verified

- **Severity:** Informational
- **Location:** `frontend/src/lib/AppState.svelte.ts`, page components.
- **Finding:** Global state is a single rune-based class instance with small setters (matches
  the documented pattern), `$derived` is used for computed values (not `$effect`), and effects
  that add listeners return cleanup functions (`AppSidebar.svelte:88-93`). No legacy `$:` or
  `svelte/store` for new code. Good.
