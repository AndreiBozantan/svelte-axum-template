# Authorization Architecture (target design)

Forward-looking design for the roles/permissions feature, chosen with the maintainer:

- **Roles:** DB-driven, tenant-customizable (composed from a fixed code-defined action catalog).
- **Tenancy:** many-to-many memberships (global user accounts, a role per tenant).
- **Entity access:** generic ACL table (ReBAC-lite), children inherit from parents.
- **Ships as:** a real `projects` + `tasks` reference feature that replaces the `sample`
  placeholder.

This supersedes the "pick a direction" recommendations in
[02](02-authorization-access-control.md) 2.1/2.2 and settles the tenancy question in
[10](10-database-data-layer.md) 10.3 (→ real multi-tenancy).

---

## Three layers (keep them distinct)

1. **Authentication** — who you are. Exists today (JWT).
2. **Tenant membership + RBAC** — *within a tenant*, which actions your role permits.
   Coarse: "may this user create projects in tenant T?"
3. **Resource access (ReBAC ACL)** — *which specific entities* you may act on.
   Fine: "may this user view project P / task X?"

A request is authorized when all three pass. RBAC gates the endpoint; the ACL gates the row.

---

## Data model

### Tenancy & membership

- `tenants` — exists.
- `users` — becomes a **global account** (drop the single `tenant_id` FK). Keep
  `UNIQUE(email)` global (a user is one account across tenants) — this resolves the
  [10.3](10-database-data-layer.md) email-uniqueness tension cleanly.
- `tenant_memberships (id, user_id, tenant_id, role_id, status, created_at)`,
  `UNIQUE(user_id, tenant_id)`. This is the user↔tenant link and where the per-tenant role
  lives.

### RBAC (DB-driven roles, code-defined action catalog)

- **Permission catalog = a fixed Rust enum** (`project:read`, `project:write`,
  `task:read`, `task:write`, `member:invite`, `role:manage`, ...). The *vocabulary of
  actions* is a code fact — you cannot grant an action the code never checks — so it stays
  in code even though roles are DB-driven.
- `roles (id, tenant_id NULL, name, is_system)` — `tenant_id NULL` = seeded system roles
  (owner/admin/member/client); non-null = a tenant's custom role.
- `role_permissions (role_id, permission)` — the mapping admins edit. `permission` is a
  string validated against the enum on write (reject unknown actions).

### ReBAC (entity-level access)

- `object_access (id, tenant_id, object_type, object_id, user_id, relation, created_at)`,
  `UNIQUE(user_id, object_type, object_id)`. `relation` ∈ {`owner`,`editor`,`viewer`}.
  `object_type` values come from a **code-side registry enum** (no free strings).
- **Inheritance** (task → its project) is resolved in the query/service layer, not stored.
- Trade-off you accepted (noted in the review): `object_type`/`object_id` are not real
  foreign keys, so integrity is app-enforced. Mitigate with: always scope by `tenant_id`,
  delete grants when the object is deleted (in the same transaction), and a periodic
  orphan-sweep task.

### Invitations (owner invites client)

- `invitations (id, tenant_id, email, role_id, token_hash, invited_by, expires_at,
  accepted_at)`. Single-use, short-lived, **hashed** token (reuse refresh-token storage
  patterns). Requires the mailer from [01](01-authentication-session.md) 1.9. Accepting
  creates/links a membership (and, for entity-scoped invites like "client on project P",
  an `object_access` row).

---

## Claims & active-tenant (the critical constraint)

Because roles and grants are mutable at runtime, **do not put roles or permission sets in
the JWT** — they would be stale after any edit/revoke. The access token carries only
`user_id` + `active_tenant_id` (+ optionally `membership_id`). Everything else is resolved
per request.

- **Active tenant:** a user in many tenants must scope each request to one. Put
  `active_tenant_id` in the access token; add `POST /api/auth/switch-tenant` that verifies
  membership and re-issues the token. (Alternative considered: tenant in the URL path —
  more RESTful but noisier; token-carried is simpler for an SPA.)
- **Resolution cost:** permission/ACL checks hit the DB. Use a request-scoped cache (resolve
  a user's membership+permissions once per request), and optionally a small TTL cache keyed
  by `(user_id, tenant_id)` **with explicit invalidation** on role/membership change. Start
  without the TTL cache; add it only if measured.

---

## Enforcement pattern (make it declarative and hard to forget)

- `Authenticated` extractor → `user_id` (exists).
- `TenantContext` extractor → loads the membership for `(user, active_tenant)`; `403` if
  none. Exposes the role + resolved permission set for the request.
- `RequirePermission(perm)` guard → RBAC check on a route. Declarative, e.g.
  `.route_layer(require(Permission::ProjectWrite))`.
- `authorize_resource(ctx, object_type, object_id, needed_relation)` helper → the ACL check
  (with parent inheritance) used inside handlers that take a resource id. Returns `404` on
  failure (per `conventions.md` §6 — don't reveal existence).

This is the shared convention [02](02-authorization-access-control.md) 2.4 asks for: new
endpoints inherit it instead of re-deriving ownership ad hoc.

---

## Reference feature: projects + tasks

Ship a minimal but real bounded context in `backend/app/` (replacing `sample`), wired end
to end so it is the pattern new features copy:

- Schema: `projects (id, tenant_id, name, created_by, ...)`, `tasks (id, project_id, ...)`.
  Project sharing via `access_grants (object_type='project')`; task access inherited from
  its project.
- `_api / _service / _db` triplet; all queries tenant-scoped; `RequirePermission` on the
  routes and `authorize_resource` on the per-project/-task handlers.
- Tests that assert the boundary, not just the happy path:
  - owner sees all projects in the tenant;
  - invited client sees only projects they hold a grant on, and only tasks within those;
  - cross-tenant access is denied (`404`);
  - a user with `member` role but no grant on project P cannot read P's tasks.
- utoipa annotations → `cargo xtask openapi` → generated client; a simple frontend
  Projects/Tasks page consuming it.

---

## How this resolves existing findings

| Finding | Resolution |
| :-- | :-- |
| [02](02-authorization-access-control.md) 2.1 (user enumeration) | `list_users` becomes an admin-permission-gated, membership-scoped query |
| [02](02-authorization-access-control.md) 2.2 (no role model) | RBAC layer above |
| [02](02-authorization-access-control.md) 2.4 (no ownership convention) | `authorize_resource` helper |
| [10](10-database-data-layer.md) 10.3 (email UNIQUE vs tenancy) | global users + memberships → keep global `UNIQUE(email)` |
| [20](20-business-logic-correctness.md) 20.1 (admin identity) | role via membership; drop id-based guesses |
| [20](20-business-logic-correctness.md) 20.2 (unused lifecycle) | self-signup → create tenant + owner membership; invite → membership |
| [09](09-frontend-code-quality.md) 9.3 (fake `isAdmin`) | replace with real permissions from `/api/users/me` |
| [07](07-code-structure-architecture.md) 7.4, [11](11-api-design.md) 11.1 (`sample`) | replaced by the projects/tasks reference feature |

---

## Suggested build order (also folded into the backend/frontend plans)

1. Multi-tenant + memberships schema; global users; self-signup creates tenant + owner
   membership; migrate away from `tenant_id = 0`.
2. RBAC: permission enum, `roles`/`role_permissions`, seed system roles, `TenantContext` +
   `RequirePermission`; gate `list_users`.
3. `switch-tenant` endpoint + active-tenant claim; expose permissions in `UserInfo`.
4. ReBAC: `object_access`, `authorize_resource` helper (+ inheritance).
5. Invitations (needs the mailer from 1.9 / email verification from 1.8).
6. Projects + tasks reference feature with boundary tests; retire `sample`.
7. Frontend: permission-aware nav/guards, tenant switcher, invite UI, projects/tasks page.
