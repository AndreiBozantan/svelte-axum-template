# Stabilization Master Plan

The single plan for taking the codebase from "reviewed template" to "solid, production-ready
platform to build an app on". It merges the former backend/frontend stabilization plans, the
authorization design, and the execution-order doc into one timeline. The numbered findings
files ([01](01-authentication-session.md)–[21](21-general-hygiene.md)) remain the evidence
base: links point to the finding with full context and the recommended fix, and each checkbox
can become one GitHub issue.

## Guiding principles

- **Quality and architecture first.** The app is small, not deployed, and has no users. The
  goal is a clean, production-grade foundation — so prefer the *right* design over the
  backward-compatible one. Nothing in the current code is set in stone; refactors and rewrites
  are in scope wherever the existing organization falls short.
- **Breaking changes are free right now.** Schema, API, JWT-claim, and config changes cost
  nothing today and get more expensive with every deploy and user. Make them early.
- **Don't polish code you're about to rewrite.** The authorization refactor (Stage B) rewrites
  registration, `UserInfo`, the users endpoint, and `sample` — those get no cosmetic work
  before it.
- **Land small, individually green PRs.** Every step leaves `cargo clippy`, tests, and the
  frontend checks passing. The big refactor ships as ~a dozen reviewable PRs, not one branch.

## Architecture decisions (settled 2026-07-02)

These supersede the "pick a direction" recommendations in
[02 § 2.1/2.2](02-authorization-access-control.md) and [10 § 10.3](10-database-data-layer.md):

- **Tenancy: real multi-tenancy with many-to-many memberships.** Users are global accounts;
  `tenant_memberships` links user↔tenant with a role per tenant. `users.tenant_id` is dropped;
  the global `UNIQUE(email)` becomes *correct* (resolving the 10.3 tension).
- **Roles: DB-driven custom roles, tenant-scoped.** The permission *catalog* (the set of
  checkable actions) stays a fixed Rust enum — only role→permission groupings live in the DB.
  System roles (owner/admin/member/client) are seeded and immutable.
- **Entity access: generic ACL table (ReBAC-lite)** for restricted roles; broad roles see the
  whole tenant via RBAC (see the resolution rule below). Children inherit from parents.
- **Scaffolding: a real `projects` + `tasks` reference feature** in `backend/app/` replaces the
  `sample` placeholder and becomes the copy-me pattern for new features.
- **Environment selection:** `env` comes only from the process environment, never from a config
  file — [15 § 15.1/15.3](15-configuration-environment.md),
  [16 § 16.1](16-containerization-deployment.md).

---

# Part 1 — Authorization design (target)

## Three layers (keep them distinct)

1. **Authentication** — who you are. Exists today (JWT).
2. **Tenant membership + RBAC** — *within a tenant*, which actions your role permits.
   Coarse: "may this user create projects in tenant T?"
3. **Resource access (ReBAC ACL)** — *which specific entities* you may act on.
   Fine: "may this user view project P / task X?"

A request is authorized when all applicable layers pass. RBAC gates the endpoint; the ACL
gates the row.

## Resource access resolution (who sees what)

A user reaches an entity through one of two paths, checked in order:

1. **Tenant-wide via RBAC.** Broad roles (owner, admin) hold tenant-scoped permissions like
   `project:read`, so a tenant admin sees **all projects in their tenant** — and all their
   tasks — with no ACL rows at all. This is the cheap check; do it first.
2. **Per-entity via ACL.** Restricted roles (e.g. `client`) hold no tenant-wide read. They see
   exactly the entities granted to them in `object_access`, plus children by inheritance
   (tasks of a granted project).

Consequences:

- ACL rows exist **only for restricted access**; assigning a project to an admin is a no-op.
- **Client assignment flow:** a project is assigned to a client (customer) by email. If the
  client is not yet a member, the *invitation* stores the project grants; accepting it creates
  the membership **and** the `object_access` rows in one transaction — so the client lands in
  the app already seeing their assigned projects and related tasks. If they are already a
  member, assignment just inserts the ACL row.
- Direct user links on entities (`created_by`, a task's assignee) are metadata, not access —
  access decisions flow only through the two paths above, so the rules live in one place.

## Data model

### Tenancy & membership

- `tenants` — exists.
- `users` — a **global account** (drop the single `tenant_id` FK). Keep `UNIQUE(email)`.
- `tenant_memberships (id, user_id, tenant_id, role_id, status, created_at)`,
  `UNIQUE(user_id, tenant_id)` — the user↔tenant link and where the per-tenant role lives.

### RBAC (DB-driven roles, code-defined action catalog)

- **Permission catalog = a fixed Rust enum** (`project:read`, `project:write`, `task:read`,
  `task:write`, `member:invite`, `role:manage`, ...) with stable string forms used in DB rows
  and docs. The vocabulary of actions is a code fact — you cannot grant an action the code
  never checks — so it stays in code even though roles are DB-driven.
- `roles (id, tenant_id NULL, name, is_system)` — `tenant_id NULL` = seeded system roles
  (owner/admin/member/client); non-null = a tenant's custom role.
- `role_permissions (role_id, permission)` — the mapping admins edit; `permission` is
  validated against the enum on write (reject unknown actions).

### ReBAC (entity-level access)

- `object_access (id, tenant_id, object_type, object_id, user_id, relation, created_at)`,
  `UNIQUE(user_id, object_type, object_id)`. `relation` ∈ {`owner`,`editor`,`viewer`}.
  `object_type` values come from a **code-side registry enum** (no free strings).
- **Inheritance** (task → its project) is resolved in the query/service layer, not stored.
- Accepted trade-off: `object_type`/`object_id` are not real foreign keys, so integrity is
  app-enforced. Mitigate: always scope by `tenant_id`; delete grants when the object is
  deleted (same transaction, service layer — and test it); periodic orphan-sweep task.

### Invitations

- `invitations (id, tenant_id, email, role_id, token_hash, invited_by, expires_at,
  accepted_at)` + a child table (or JSON column) for **carried entity grants** (the client
  assignment flow above). Single-use, short-lived, **hashed** token (reuse refresh-token
  storage patterns). Requires the mailer ([01 § 1.9](01-authentication-session.md)).

## Claims & active tenant (the critical constraint)

Roles and grants are mutable at runtime, so **do not put roles or permission sets in the
JWT** — they would be stale after any edit/revoke. The access token carries only `user_id` +
`active_tenant_id` (+ optionally `membership_id`); everything else is resolved per request.

- **Active tenant:** `POST /api/auth/switch-tenant` verifies membership and re-issues the
  token. (Alternative considered: tenant in the URL path — more RESTful but noisier;
  token-carried is simpler for an SPA.)
- **Resolution cost:** use a request-scoped cache (resolve membership+permissions once per
  request). Add a TTL cache keyed by `(user_id, tenant_id)` with explicit invalidation only
  if measured (see Deferred).

## Enforcement pattern (declarative and hard to forget)

- `Authenticated` extractor → `user_id` (exists).
- `TenantContext` extractor → loads the membership for `(user, active_tenant)`; `403` if
  none. Exposes the role + resolved permission set for the request.
- `RequirePermission(perm)` guard → RBAC check on a route, e.g.
  `.route_layer(require(Permission::ProjectWrite))`.
- `authorize_resource(ctx, object_type, object_id, needed_relation)` helper → the resolution
  rule above (RBAC tenant-wide first, then ACL with parent inheritance). Returns `404` on
  failure per `conventions.md` §6 (don't reveal existence).

This is the shared convention [02 § 2.4](02-authorization-access-control.md) asks for: new
endpoints inherit it instead of re-deriving ownership ad hoc.

## How this resolves existing findings

| Finding | Resolution |
| :-- | :-- |
| [02 § 2.1](02-authorization-access-control.md) (user enumeration) | `list_users` becomes a permission-gated, membership-scoped query |
| [02 § 2.2](02-authorization-access-control.md) (no role model) | the RBAC layer |
| [02 § 2.4](02-authorization-access-control.md) (no ownership convention) | `authorize_resource` helper |
| [10 § 10.3](10-database-data-layer.md) (email UNIQUE vs tenancy) | global users + memberships |
| [20 § 20.1](20-business-logic-correctness.md) (admin identity) | role via membership; drop id-based guesses |
| [20 § 20.2](20-business-logic-correctness.md) (unused lifecycle) | signup → tenant + owner membership; invite → `onboarding` member |
| [09 § 9.3](09-frontend-code-quality.md) (fake `isAdmin`) | real permissions from `/api/users/me` |
| [07 § 7.4](07-code-structure-architecture.md), [11 § 11.1](11-api-design.md) (`sample`, `/api/api`) | retired by the projects/tasks reference feature |

---

# Part 2 — The staged plan

**The ordering principle: don't invest in code you're about to rewrite, and make the schema
change while it's still free.** The authorization refactor goes as early as its prerequisites
allow — after the cheap, independent work that protects and unblocks it.

## Stage A — Cheap, independent, protective (do first)

No ordering constraints among these; none is invalidated by the Stage B refactor.

Shipped frontend bugs:

- [ ] Failed login leaves Sign In permanently disabled — [09 § 9.1](09-frontend-code-quality.md)
- [ ] `Logout.svelte` renders `[object Object]`; logout result ignored — [09 § 9.2](09-frontend-code-quality.md)
- [ ] Silent bootstrap failure leaves a blank page — [09 § 9.10](09-frontend-code-quality.md)

Security fixes that don't touch the auth model:

- [ ] Enforce `user.status` on login and refresh; revoke tokens on suspend —
      [01 § 1.1](01-authentication-session.md)
- [ ] Trusted-proxy handling: only honor `X-Forwarded-For`/`X-Real-IP` behind an explicit
      config flag — [01 § 1.3](01-authentication-session.md),
      [05 § 5.3](05-http-transport-security.md), [19 § 19.3](19-performance-scalability.md)
- [ ] Security response headers (nosniff, frame-ancestors, CSP, HSTS, Referrer-Policy) —
      [05 § 5.1](05-http-transport-security.md)
- [ ] Request body limit + password/name max-length validation (hash-amplification DoS) —
      [03 § 3.1/3.2](03-input-validation-injection.md)
- [ ] Request timeout layer; timeout on the OAuth token exchange —
      [13 § 13.1/13.2](13-error-handling-resilience.md)
- [ ] Graceful shutdown on SIGTERM (container rollouts) —
      [13 § 13.3](13-error-handling-resilience.md)
- [ ] Document the mandatory TLS-terminating proxy assumption —
      [05 § 5.2](05-http-transport-security.md)
- [ ] OAuth consent screen is not shown during Google sign-in — investigate the auth-URL
      parameters (`prompt`, scopes) and fix so the user sees/approves what is granted
      *(new item, no finding number)*

Configuration correctness:

- [ ] Environment selection: `env` only from the process environment; remove it from all TOML
      layers; set it in Dockerfile/compose/xtask — [15 § 15.1/15.3](15-configuration-environment.md),
      [16 § 16.1](16-containerization-deployment.md)
- [ ] Fail-fast config validation at startup (esp. production) —
      [15 § 15.2](15-configuration-environment.md)

Decisions that gate later work:

- [ ] Frontend routing: adopt `svelte-spa-router` or finish the custom router (click
      interception, shared `pathToPage()`, 404 route) — **before any new pages exist** —
      [09 § 9.4](09-frontend-code-quality.md)

Tooling that protects every later commit:

- [ ] CI supply-chain gating: `cargo audit`/`cargo deny` + `npm audit` as PR gates; Semgrep on
      PRs; Dependabot/Renovate — [06 § 6.1/6.2](06-dependency-supply-chain.md),
      [17 § 17.1](17-cicd.md)
- [ ] Enforce code styling for frontend and backend through tooling: `.editorconfig`, and
      `rustfmt`/`prettier`/`svelte-check` enforced in both the git hooks and CI, so style is
      never a review topic *(new item)*

## Stage B — The authorization & multi-tenancy refactor (the spine)

Implements Part 1, landed as **small, individually green PRs** in this order. Resolves
[02 § 2.1/2.2](02-authorization-access-control.md), [10 § 10.3](10-database-data-layer.md),
[20 § 20.1/20.2](20-business-logic-correctness.md). Multi-write flows (signup→tenant→membership,
invite acceptance) are wrapped in transactions **as they are written**, not retrofitted —
[10 § 10.2](10-database-data-layer.md), [20 § 20.5](20-business-logic-correctness.md).

- [ ] Permission catalog: Rust enum of actions with stable string forms
- [ ] Schema migration: drop `users.tenant_id`; add `tenant_memberships`, `roles`,
      `role_permissions`; seed immutable system roles (owner, admin, member, client)
- [ ] Registration/SSO flow: self-signup creates tenant + owner membership; adapt
      `link_sso_user` to the new schema
- [ ] Mailer abstraction (trait + dev console impl + one provider) — prerequisite for
      verification here and invites below — [01 § 1.9](01-authentication-session.md)
- [ ] Email verification on registration + fix SSO auto-linking (account pre-hijacking) —
      [01 § 1.8](01-authentication-session.md), [20 § 20.3](20-business-logic-correctness.md)
- [ ] User lifecycle: `onboarding → active → suspended/archived` transitions (invited users
      start in `onboarding` until first login) — [20 § 20.2](20-business-logic-correctness.md)
- [ ] JWT claims: replace `tenant_id` with `active_tenant_id`; add `POST /api/auth/switch-tenant`
- [ ] Authorization machinery: `TenantContext` + `RequirePermission` extractors, the
      permission-resolution service (request-scoped), 404-on-denied per `conventions.md` §6
- [ ] Role management endpoints: tenant-admin CRUD for custom roles + assignment; system roles
      immutable; covered by tests (the cost of the DB-driven choice — budget for it)
- [ ] Invite flow: owner/admin invites an email with a role **and optional entity grants**
      (the client-assignment flow); single-use hashed token; accept creates membership + ACL
      rows in one transaction
- [ ] Entity ACL: `object_access` + `authorize_resource` helper (RBAC-first resolution rule,
      parent inheritance); service-layer ACL cleanup on entity delete + test
- [ ] Reference feature `projects` + `tasks` in `backend/app/`: full `_api/_db/_service` +
      utoipa + regenerated client + **boundary tests** (owner/admin sees all tenant projects;
      client sees only assigned projects and their tasks; cross-tenant → 404; member without a
      grant on P cannot read P's tasks) — replaces `sample`, which retires
      [07 § 7.4](07-code-structure-architecture.md) and the `/api/api/sample` path
      [11 § 11.1](11-api-design.md)
- [ ] Rework `GET /api/users` into a tenant-scoped member listing gated by
      `tenant:manage_members` — closes [02 § 2.1](02-authorization-access-control.md)
- [ ] Expose the caller's permission set in `UserInfo` so the frontend derives UI capabilities
      — [09 § 9.3](09-frontend-code-quality.md)

## Stage C — Frontend catches up (overlaps the tail of Stage B)

As each backend capability lands, the matching frontend work unblocks.

- [ ] Retire `isAdmin` (`user.id === 1`): capability helpers on `AppState` — `can(permission)`
      derived from the backend permission set; nav visibility and route guards use `can(...)` —
      [09 § 9.3](09-frontend-code-quality.md)
- [ ] Align error codes across backend + frontend: frontend expects `not_authenticated`,
      backend emits `invalid_token`/`expired_token`; settle the canonical `code` set in
      `conventions.md` — [09 § 9.8](09-frontend-code-quality.md), [11 § 11.3](11-api-design.md),
      [18 § 18.1](18-documentation-dx.md)
- [ ] Tenant switcher UI for users with multiple memberships
- [ ] Invite UI (owner/admin invites an email + role + project assignment) and an
      invitation-accept page
- [ ] Projects/tasks page consuming the generated client — the frontend half of the reference
      feature (owner sees all, client sees only assigned)

## Stage D — Hardening & polish (surface is now stable)

Backend resilience & operability:

- [ ] Argon2 hashing via `spawn_blocking` — [19 § 19.1](19-performance-scalability.md)
- [ ] `PRAGMA synchronous = NORMAL` explicit; pool acquire timeout; document backup strategy —
      [10 § 10.1/10.7](10-database-data-layer.md)
- [ ] `X-Request-ID` generation/propagation in the trace span — [14 § 14.1](14-logging-observability.md)
- [ ] Supervise/log background cleanup-task exits — [13 § 13.4](13-error-handling-resilience.md)
- [ ] Container healthcheck; drop obsolete compose `version` key —
      [16 § 16.2/16.3](16-containerization-deployment.md)
- [ ] Response compression (`CompressionLayer`) — [19 § 19.6](19-performance-scalability.md)
- [ ] Gate `/health?panic=true` to non-prod; consider `/ready` split —
      [14 § 14.4](14-logging-observability.md), [13 § 13.5](13-error-handling-resilience.md)

API contract coherence (code, docs, and client must agree):

- [ ] Pagination: implement the documented cursor shape or relax the convention — applies to
      the new member/project/task list endpoints — [11 § 11.2](11-api-design.md),
      [19 § 19.2](19-performance-scalability.md)
- [ ] `#[serde(deny_unknown_fields)]` on request DTOs (or fix the doc) — [03 § 3.3](03-input-validation-injection.md)
- [ ] `Retry-After` on 429 — [11 § 11.4](11-api-design.md)
- [ ] Reconcile `conventions.md` with reality; mark unimplemented sections — [18 § 18.1](18-documentation-dx.md)

Account management (nearly free once the Stage B mailer exists):

- [ ] Change-password (requires current password, revokes other sessions) and
      forgot/reset-password (single-use hashed token) — [01 § 1.9](01-authentication-session.md)
- [ ] Account deletion/anonymization path (uses the `archived` status) — [10 § 10.6](10-database-data-layer.md)
- [ ] Account-lockout DoS trade-off: cap duration or add IP-scoped throttle — [01 § 1.4](01-authentication-session.md)

Frontend standards, UX & accessibility:

- [ ] `About.svelte` raw `fetch` → `api.health.health_check()` — [09 § 9.5](09-frontend-code-quality.md)
- [ ] `fetch.ts` `onError`: distinguish offline from server error, snake_case code, dev log —
      [09 § 9.7](09-frontend-code-quality.md)
- [ ] Type `PageDefinition.component` as `Component` instead of `any` — [09 § 9.6](09-frontend-code-quality.md)
- [ ] Logout confirm is hover-only (keyboard users bypass it); make click-toggled + Escape —
      [09 § 9.9](09-frontend-code-quality.md)
- [ ] Settings toggles are non-functional placeholders; wire up or mark — [09 § 9.9](09-frontend-code-quality.md)
- [ ] `auth-refresh-manager`: simplicity & safety pass — fix the stale-timer edge (gate
      `focus`/`storage` rescheduling on `AppState.isLoggedIn`, clear timing keys on auth
      failure, [01 § 1.6](01-authentication-session.md)); then simplify where possible without
      losing the tested behaviors ([09 § 9.11](09-frontend-code-quality.md),
      [12 § 12.4](12-testing.md) rate it the strongest frontend code — keep it that way)

## Stage E — Lock it in

Tests (the authorization *boundary* tests already shipped inside Stage B):

- [ ] Role/permission-resolution unit tests, incl. custom roles and system-role immutability —
      [02 § 2.2](02-authorization-access-control.md)
- [ ] Make Google HTTP calls injectable; test the OAuth callback (CSRF mismatch, expired
      state, happy path) — [12 § 12.2](12-testing.md)
- [ ] Suspended-user login/refresh rejection tests — [01 § 1.1](01-authentication-session.md)
- [ ] Pre-hijack scenario test (register → SSO link) — [01 § 1.8](01-authentication-session.md)
- [ ] Component tests for Login and auth-redirect logic; remove `dummy.test.ts`; optional
      Playwright smoke test (login → protected page → logout) — [12 § 12.4](12-testing.md)

Remaining CI/CD:

- [ ] Run `sqlx prepare --check` in CI — [17 § 17.2](17-cicd.md)
- [ ] License allow-list (`cargo deny check licenses`) — [06 § 6.5](06-dependency-supply-chain.md)
- [ ] Release workflow: tag → build → push image; documented rollback — [17 § 17.3](17-cicd.md)

Backend hygiene (batch into few issues):

- [ ] Service-layer cleanups: drop the HTTP error variant from `auth::Error`; make repo/context
      fields non-`pub`; stop api→repo reach-through — [07 § 7.1/7.2](07-code-structure-architecture.md)
- [ ] `map_err` → `#[from]` sweep; comment or remove clippy allows; `#[cfg(test)]` for
      test-only code; avoid the `Row` clone — [08 § 8.1/8.3/8.4/8.5](08-rust-code-quality.md)
- [ ] Curate startup config logging; stop logging CSRF hashes —
      [04 § 4.1/4.2](04-scrts-sensitive-data.md), [14 § 14.3](14-logging-observability.md)
- [ ] Pick one `updated_at` mechanism (trigger vs explicit) — [10 § 10.4](10-database-data-layer.md)
- [ ] `xtask` overhaul: move the inline `dev`/`release`/`clean`/`dev_init` logic into modules,
      clean up the code, make the styling consistent with the backend, and add small shared
      abstractions (command-running, port-waiting, process supervision helpers) to reduce
      overall size — extends [07 § 7.3](07-code-structure-architecture.md)
- [ ] Docs: config reference, README architecture/testing sections, import-style convention
      decision — [15 § 15.4](15-configuration-environment.md),
      [18 § 18.2/18.3](18-documentation-dx.md), [21 § 21.4](21-general-hygiene.md)

Frontend hygiene (batch into one issue):

- [ ] Dead `/user_info.js` proxy; runtime Google Fonts import / unloaded Inter; hardcoded
      `v1.0.0-beta`; global `isLoading` misuse in SecureApi — [09 § 9.10](09-frontend-code-quality.md)
- [ ] `console.*` calls in production code — [21 § 21.1](21-general-hygiene.md)
- [ ] Commented-out code, dead `AppState.userId`, package name drift —
      [21 § 21.2/21.3/21.5](21-general-hygiene.md)

## Deferred (document, revisit when needed)

- JWT key rotation (`kid` + multiple decode keys) — [04 § 4.3](04-scrts-sensitive-data.md)
- Access-token deny-list for instant logout — [01 § 1.2](01-authentication-session.md)
- Application metrics (`/metrics`, RED) — [14 § 14.2](14-logging-observability.md)
- Idempotency keys for mutating endpoints — [11 § 11.5](11-api-design.md)
- SQLite write-throughput ceiling / Postgres path — [19 § 19.4](19-performance-scalability.md)
- Permission-resolution TTL cache with invalidation (only if measured)
- Lazy-load page components / bundle splitting — [19 § 19.5](19-performance-scalability.md)
- Extract `auth-refresh-manager` as a standalone npm package (after the Stage D
  simplicity/safety pass proves the API surface is stable)

---

## Why this order (and not the others)

- **Authz last** (all polish first): you'd polish `list_users`, `sample`, `UserInfo`, and
  registration — all rewritten by Stage B — and carry the tenant-0 disclosure the whole time.
- **Authz literally first** (before Stage A): the biggest change on top of a base that still
  drops SIGTERM requests, has no body limits, and no CI security gate. Stage A is a day or two
  of cheap insurance that makes the refactor safer to land.

**The one dependency to watch:** the only frontend items that must wait for backend Stage B
are the `isAdmin`→permissions change and the error-code alignment. Everything else in Stages
A/C/D frontend work is independent and can proceed in parallel.
