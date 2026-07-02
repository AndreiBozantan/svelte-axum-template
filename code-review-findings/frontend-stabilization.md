# Frontend Stabilization Plan

References to all frontend-related findings, ordered as a suggested work plan. Each item can
become one GitHub issue; links point to the finding with full context and the recommended fix.

## Phase 1 — Fix shipped bugs (quick wins)

- [ ] Failed login leaves Sign In button permanently disabled — [09 § 9.1](09-frontend-code-quality.md)
- [ ] `Logout.svelte` renders `[object Object]`; logout result ignored — [09 § 9.2](09-frontend-code-quality.md)
- [ ] Silent bootstrap failure leaves a blank page — [09 § 9.10](09-frontend-code-quality.md)

## Phase 2 — Settle the architecture (do before adding app pages)

- [ ] Routing: nav links do full page reloads; adopt `svelte-spa-router` or finish the custom
      router (click interception, shared `pathToPage()`, 404 route) — [09 § 9.4](09-frontend-code-quality.md)
- [ ] Replace `isAdmin` (`user.id === 1`) with a real capability model derived from the
      backend permission set on `UserInfo` — [09 § 9.3](09-frontend-code-quality.md), depends on
      [02 § 2.2](02-authorization-access-control.md) / [authorization-design.md](authorization-design.md)
- [ ] Align error codes: frontend expects `not_authenticated`, backend emits
      `invalid_token`/`expired_token` — [09 § 9.8](09-frontend-code-quality.md),
      [11 § 11.3](11-api-design.md), [18 § 18.1](18-documentation-dx.md)
- [ ] Regenerate client after fixing the duplicated `/api/api/sample` path (backend fix) —
      [11 § 11.1](11-api-design.md)

## Phase 3 — Project standards & consistency

- [ ] `About.svelte` uses raw `fetch`; switch to `api.health.health_check()` —
      [09 § 9.5](09-frontend-code-quality.md)
- [ ] `fetch.ts` `onError`: distinguish offline from server error, snake_case code, dev log —
      [09 § 9.7](09-frontend-code-quality.md)
- [ ] Type `PageDefinition.component` as `Component` instead of `any` —
      [09 § 9.6](09-frontend-code-quality.md)

## Phase 4 — UX & accessibility

- [ ] Logout confirm: hover-only, keyboard users bypass it; make click-toggled + Escape —
      [09 § 9.9](09-frontend-code-quality.md)
- [ ] Settings toggles are non-functional placeholders; wire up or mark —
      [09 § 9.9](09-frontend-code-quality.md)

## Phase 4.5 — Access-control UI (follows the backend authorization build-out)

Consumes the [authorization design](authorization-design.md); depends on the backend exposing
permissions in `UserInfo`, the tenant-switch endpoint, and the projects/tasks + invite APIs.

- [ ] Capability helpers on `AppState`: derive `can(permission)` from the backend permission
      set; drive nav visibility and route guards off `can(...)` instead of `isAdmin` —
      [09 § 9.3](09-frontend-code-quality.md)
- [ ] Tenant switcher UI for users with multiple memberships (calls the switch-tenant endpoint,
      refreshes the session) — [authorization-design.md](authorization-design.md)
- [ ] Invite UI (owner/admin invites an email + role) and an invitation-accept page
- [ ] Projects/tasks reference page: consumes the generated client for the new reference
      feature; owner sees all, client sees only granted projects — the frontend half of the
      backend reference feature

## Phase 5 — Tests (lock in the fixes)

- [ ] Component tests for Login (error re-enables button, disabled-while-pending) and
      auth-redirect logic; remove `dummy.test.ts` — [12 § 12.4](12-testing.md)
- [ ] Optional: minimal Playwright smoke test (login → protected page → logout) —
      [12 § 12.4](12-testing.md)

## Phase 6 — Hygiene (batch into one issue)

- [ ] Dead `/user_info.js` proxy, runtime Google Fonts import / unloaded Inter, hardcoded
      `v1.0.0-beta`, global `isLoading` misuse in SecureApi — [09 § 9.10](09-frontend-code-quality.md)
- [ ] `console.*` calls in production code — [21 § 21.1](21-general-hygiene.md)
- [ ] Commented-out code, dead `AppState.userId`, package name drift —
      [21 § 21.2, 21.3, 21.5](21-general-hygiene.md)

## Deferred (fine for now, revisit as the app grows)

- Lazy-load page components / bundle splitting — [19 § 19.5](19-performance-scalability.md)
- Response compression (backend `CompressionLayer`) — [19 § 19.6](19-performance-scalability.md)
