# Authorization Architecture

The target design for identity, multi-tenancy, roles/permissions, and entity-level access.
Decided 2026-07-02; implemented via Stage B of the
[stabilization plan](../../code-review-findings/stabilization-plan.md).

Summary of the chosen model:

- **Tenancy:** real multi-tenancy — users are global accounts, linked to tenants through
  many-to-many memberships with a role per tenant.
- **Roles:** DB-driven and tenant-customizable, composed from a fixed code-defined permission
  catalog; system roles are seeded and immutable.
- **Entity access:** a generic ACL table (ReBAC-lite) for restricted roles; broad roles see
  the whole tenant via RBAC; children inherit access from parents.
- **Reference implementation:** a `projects` + `tasks` bounded context in `backend/app/`,
  wired through the whole stack — the pattern new features copy.

## Three layers (keep them distinct)

1. **Authentication** — who you are (JWT).
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
- `users` — a **global account** (drop the single `tenant_id` FK). Keep `UNIQUE(email)`
  global: one account across tenants.
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
  storage patterns). Requires the mailer abstraction.

## Claims & active tenant (the critical constraint)

Roles and grants are mutable at runtime, so **do not put roles or permission sets in the
JWT** — they would be stale after any edit/revoke. The access token carries only `user_id` +
`active_tenant_id` (+ optionally `membership_id`); everything else is resolved per request.

- **Active tenant:** `POST /api/auth/switch-tenant` verifies membership and re-issues the
  token. (Alternative considered: tenant in the URL path — more RESTful but noisier;
  token-carried is simpler for an SPA.)
- **Resolution cost:** use a request-scoped cache (resolve membership+permissions once per
  request). Add a TTL cache keyed by `(user_id, tenant_id)` with explicit invalidation only
  if measured.

## Enforcement pattern (declarative and hard to forget)

- `Authenticated` extractor → `user_id` (exists).
- `TenantContext` extractor → loads the membership for `(user, active_tenant)`; `403` if
  none. Exposes the role + resolved permission set for the request.
- `RequirePermission(perm)` guard → RBAC check on a route, e.g.
  `.route_layer(require(Permission::ProjectWrite))`.
- `authorize_resource(ctx, object_type, object_id, needed_relation)` helper → the resolution
  rule above (RBAC tenant-wide first, then ACL with parent inheritance). Returns `404` on
  failure per [conventions.md](../api/conventions.md) §6 (don't reveal existence).

This is the shared authorization convention: new endpoints inherit it instead of re-deriving
ownership ad hoc.
