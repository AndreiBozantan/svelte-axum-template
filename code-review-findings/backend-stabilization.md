# Backend Stabilization Plan

References to all backend findings, ordered as a suggested work plan. Each item can become one
GitHub issue; links point to the finding with full context and the recommended fix.

## Phase 0 — Architectural decisions

**Decided 2026-07-02** (supersedes the original recommendations in
[02 § 2.1/2.2](02-authorization-access-control.md) and [10 § 10.3](10-database-data-layer.md)):

- **Tenancy: real multi-tenancy with many-to-many memberships.** Users are global accounts;
  a `tenant_memberships` table links user↔tenant with a role per tenant. Self-signup creates
  a tenant + owner membership; invites add memberships. `users.tenant_id` is dropped; the
  global `UNIQUE(email)` on users becomes *correct* (resolving the 10.3 tension without a
  per-tenant unique).
- **Roles: DB-driven custom roles, tenant-scoped.** `roles` + `role_permissions` tables;
  tenant admins can define custom roles at runtime. **Mitigation for the two-sources-of-truth
  risk:** the permission *catalog* (the set of checkable actions) stays a fixed Rust enum —
  only role→permission groupings live in the DB. System roles (owner/admin/member/client) are
  seeded and non-editable/non-deletable, so code may safely assume their invariants.
- **Entity access: generic ACL table (ReBAC-lite).** One `object_access` table
  `(object_type, object_id, user_id, relation)`; child entities (tasks) inherit access from
  their parent (project). **Mitigations:** `object_type` values come from a code-side registry
  enum (no free strings); deleting an entity must delete its ACL rows (no FK is possible on a
  polymorphic id — enforce in the service layer or via per-type triggers, and test it).
- **Scaffolding: projects+tasks reference feature.** A minimal real bounded context in
  `backend/app/` wired through the whole stack, replacing the `sample` placeholder; serves as
  the copy-me pattern and the start of the actual app.

Remaining decisions:

- [ ] Environment selection: `env` comes only from the process environment, never from a config
      file; remove `env` from all TOML layers, set it in Dockerfile/compose/xtask —
      [15 § 15.1](15-configuration-environment.md), [15 § 15.3](15-configuration-environment.md),
      [16 § 16.1](16-containerization-deployment.md)
- [ ] User lifecycle: implement `onboarding → active → suspended/archived` transitions (invited
      users start in `onboarding` until first login; see Phase 2 invite flow) —
      [20 § 20.2](20-business-logic-correctness.md)

## Phase 1 — Security-critical fixes (small, independent; do before the big refactor)

- [ ] Enforce `user.status` on login and refresh; revoke tokens on suspend —
      [01 § 1.1](01-authentication-session.md)
- [ ] Email verification on registration + fix SSO auto-linking (account pre-hijacking) —
      [01 § 1.8](01-authentication-session.md), [20 § 20.3](20-business-logic-correctness.md);
      needs the mailer (Phase 2 prerequisite item)
- [ ] Trusted-proxy handling: only honor `X-Forwarded-For`/`X-Real-IP` behind an explicit
      config flag — [01 § 1.3](01-authentication-session.md),
      [05 § 5.3](05-http-transport-security.md), [19 § 19.3](19-performance-scalability.md)
- [ ] Security response headers (nosniff, frame-ancestors, CSP, HSTS, Referrer-Policy) —
      [05 § 5.1](05-http-transport-security.md)
- [ ] Request body limit + password/name max-length validation (hash-amplification DoS) —
      [03 § 3.1](03-input-validation-injection.md), [03 § 3.2](03-input-validation-injection.md)
- [ ] Request timeout layer; timeout on the OAuth token exchange —
      [13 § 13.1](13-error-handling-resilience.md), [13 § 13.2](13-error-handling-resilience.md)
- [ ] Document the mandatory TLS-terminating proxy assumption —
      [05 § 5.2](05-http-transport-security.md)

## Phase 2 — Access control & multi-tenancy implementation (the big one)

Implements the Phase 0 decisions. Sequence as small, individually reviewable migrations/PRs;
resolves [02 § 2.1](02-authorization-access-control.md),
[02 § 2.2](02-authorization-access-control.md), [10 § 10.3](10-database-data-layer.md),
[20 § 20.1](20-business-logic-correctness.md).

- [ ] Permission catalog: Rust enum of actions (e.g. `tenant:manage_members`, `project:create`,
      `project:read`, `task:write`, ...) with stable string forms used in DB rows and JWT/docs
- [ ] Schema migration: drop `users.tenant_id`; add `tenant_memberships(user_id, tenant_id,
      role_id)`, `roles(id, tenant_id, name, is_system)`, `role_permissions(role_id, permission)`;
      seed non-editable system roles (owner, admin, member, client)
- [ ] Registration/SSO flow: self-signup creates tenant + owner membership; adapt
      `link_sso_user` to the new schema
- [ ] JWT claims: replace `tenant_id` with active-tenant + membership context; add a
      tenant-switch endpoint for users with multiple memberships
- [ ] Authorization machinery: `RequirePermission` extractor (declarative per-route), a
      permission-resolution service (membership → role → permissions, per-request, cacheable
      later), 404-on-denied per `conventions.md` §6
- [ ] Role management endpoints: tenant-admin CRUD for custom roles + assignment; system roles
      immutable; covered by tests (this is the cost of the DB-driven choice — budget for it)
- [ ] Mailer abstraction (trait + dev console impl + one provider) — prerequisite for invites
      here and verification/reset in Phases 1/5 — [01 § 1.9](01-authentication-session.md)
- [ ] Invite flow: owner/admin invites an email into the tenant with a role; single-use hashed
      token (reuse refresh-token storage patterns); invited user lands as `onboarding` member
- [ ] Entity ACL: `object_access(object_type, object_id, user_id, relation)` with a code-side
      object-type registry; helper for "can user U do action A on object O" including
      parent-inheritance (task → project); service-layer ACL-row cleanup on entity delete + test
- [ ] Reference feature `projects` + `tasks` in `backend/app/`: full `_api/_db/_service` +
      utoipa + generated client + tests; owner/admin sees all tenant projects, `client` role
      sees only projects they hold ACL rows for; tasks inherit project access — replaces the
      `sample` placeholder ([07 § 7.4](07-code-structure-architecture.md),
      [11 § 11.1](11-api-design.md) both die with it)
- [ ] Rework `GET /api/users` into tenant-scoped member listing gated by
      `tenant:manage_members` — closes [02 § 2.1](02-authorization-access-control.md)
- [ ] Expose the caller's permission set in `UserInfo` so the frontend derives UI capabilities
      (replaces the fake `isAdmin`, [09 § 9.3](09-frontend-code-quality.md))

## Phase 3 — Resilience & operability

- [ ] Graceful shutdown on SIGTERM (container rollouts) — [13 § 13.3](13-error-handling-resilience.md)
- [ ] Wrap refresh-rotation and other multi-write flows in transactions (the Phase 2 flows —
      signup+tenant+membership, invite acceptance — are multi-write and need this from day one) —
      [10 § 10.2](10-database-data-layer.md), [20 § 20.5](20-business-logic-correctness.md)
- [ ] Argon2 hashing via `spawn_blocking` — [19 § 19.1](19-performance-scalability.md)
- [ ] Set `PRAGMA synchronous = NORMAL` explicitly; pool acquire timeout; document backup
      strategy — [10 § 10.1](10-database-data-layer.md), [10 § 10.7](10-database-data-layer.md)
- [ ] Fail-fast config validation at startup (esp. production) —
      [15 § 15.2](15-configuration-environment.md)
- [ ] `X-Request-ID` generation/propagation in the trace span —
      [14 § 14.1](14-logging-observability.md)
- [ ] Supervise/log background cleanup-task exits — [13 § 13.4](13-error-handling-resilience.md)
- [ ] Container healthcheck; drop obsolete compose `version` key —
      [16 § 16.2](16-containerization-deployment.md), [16 § 16.3](16-containerization-deployment.md)
- [ ] Response compression (`CompressionLayer`) — [19 § 19.6](19-performance-scalability.md)
- [ ] Gate `/health?panic=true` to non-prod; consider `/ready` split —
      [14 § 14.4](14-logging-observability.md), [13 § 13.5](13-error-handling-resilience.md)

## Phase 4 — API contract coherence (code, docs, and client must agree)

`/api/api/sample` (11.1) is retired by the projects/tasks reference feature in Phase 2, so it
is not repeated here.

- [ ] Canonical error `code` set across backend, docs, frontend —
      [11 § 11.3](11-api-design.md), [09 § 9.8](09-frontend-code-quality.md),
      [18 § 18.1](18-documentation-dx.md)
- [ ] Pagination: implement the documented cursor shape or relax the convention — applies to the
      new member/project/task list endpoints too —
      [11 § 11.2](11-api-design.md), [19 § 19.2](19-performance-scalability.md)
- [ ] `#[serde(deny_unknown_fields)]` on request DTOs (or fix the doc) —
      [03 § 3.3](03-input-validation-injection.md)
- [ ] `Retry-After` on 429 — [11 § 11.4](11-api-design.md)
- [ ] Reconcile `conventions.md` with reality; mark unimplemented sections —
      [18 § 18.1](18-documentation-dx.md)

## Phase 5 — Account management (remaining after the mailer lands in Phase 2)

- [ ] Change-password (authenticated, requires current password, revokes other sessions) and
      forgot/reset-password (single-use hashed token) — [01 § 1.9](01-authentication-session.md)
- [ ] Account deletion/anonymization path (uses the `archived` status) —
      [10 § 10.6](10-database-data-layer.md)
- [ ] Account-lockout DoS trade-off: cap duration or add IP-scoped throttle —
      [01 § 1.4](01-authentication-session.md)

## Phase 6 — Tests (lock in Phases 1–5)

The core authorization boundary tests ship *with* the Phase 2 feature (owner sees all; client
sees only granted projects' tasks; cross-tenant denied). The items here are the rest.

- [ ] Role/permission-resolution unit tests (membership → role → permissions), including custom
      roles and system-role immutability — [02 § 2.2](02-authorization-access-control.md)
- [ ] Make Google HTTP calls injectable; test the OAuth callback (CSRF mismatch, expired state,
      happy path) — [12 § 12.2](12-testing.md)
- [ ] Suspended-user login/refresh rejection tests — [01 § 1.1](01-authentication-session.md)
- [ ] Pre-hijack scenario test (register → SSO link) — [01 § 1.8](01-authentication-session.md)

## Phase 7 — CI/CD & supply chain

- [ ] `cargo audit`/`cargo deny` + `npm audit` as PR-gating CI; Semgrep on PRs —
      [06 § 6.1](06-dependency-supply-chain.md), [17 § 17.1](17-cicd.md)
- [ ] Dependabot/Renovate — [06 § 6.2](06-dependency-supply-chain.md)
- [ ] License allow-list (`cargo deny check licenses`) — [06 § 6.5](06-dependency-supply-chain.md)
- [ ] Run `sqlx prepare --check` in CI — [17 § 17.2](17-cicd.md)
- [ ] Release workflow: tag → build → push image; documented rollback — [17 § 17.3](17-cicd.md)

## Phase 8 — Code quality & hygiene (batch into few issues)

- [ ] Service-layer cleanups: drop the HTTP error variant from `auth::Error`; make repo/context
      fields non-`pub`; stop api→repo reach-through — [07 § 7.1, 7.2](07-code-structure-architecture.md)
- [ ] `map_err` → `#[from]` sweep; comment or remove clippy allows; `#[cfg(test)]` for
      test-only code; avoid the `Row` clone — [08 § 8.1, 8.3, 8.4, 8.5](08-rust-code-quality.md)
- [ ] Curate startup config logging; stop logging CSRF hashes —
      [04 § 4.1, 4.2](04-scrts-sensitive-data.md), [14 § 14.3](14-logging-observability.md)
- [ ] Pick one `updated_at` mechanism (trigger vs explicit) — [10 § 10.4](10-database-data-layer.md)
- [ ] xtask module split — [07 § 7.3](07-code-structure-architecture.md)
- [ ] Docs: config reference, README architecture/testing sections, import-style convention
      decision — [15 § 15.4](15-configuration-environment.md), [18 § 18.2, 18.3](18-documentation-dx.md),
      [21 § 21.4](21-general-hygiene.md)

## Deferred (document, revisit when needed)

- JWT key rotation (`kid` + multiple decode keys) — [04 § 4.3](04-scrts-sensitive-data.md)
- Access-token deny-list for instant logout — [01 § 1.2](01-authentication-session.md)
- Application metrics (`/metrics`, RED) — [14 § 14.2](14-logging-observability.md)
- Idempotency keys for mutating endpoints — [11 § 11.5](11-api-design.md)
- SQLite write-throughput ceiling / Postgres path — [19 § 19.4](19-performance-scalability.md)
- Permission-resolution caching (per-request first; TTL cache with invalidation only if
  measured) — [authorization-design.md](authorization-design.md)