# Authorization Architecture

The durable design for identity, multi-tenancy, roles/permissions, and entity-level access.
Decided 2026-07-02; revised 2026-07-03 (relationship-based access, no active tenant).
Implemented via Stage B of the
[stabilization plan](../../code-review-findings/stabilization-plan.md). The concrete DDL,
queries, and task list live in the **Implementation Plan** at the bottom and are deleted once
Stage B ships — this architecture is what remains.

The model in brief:

- **Global users, real multi-tenancy.** Users are global accounts linked to tenants through
  `tenant_memberships`, one role per tenant. Internal staff and external client contacts are
  both memberships; the role distinguishes them.
- **No active tenant.** The access token carries only `user_id`; queries return the **union**
  across every tenant the user belongs to (a client sees their projects in all tenants at once).
  No tenant-selection step, no per-tenant token re-issue.
- **DB-driven roles over a code-defined permission catalog.** System roles are seeded and
  immutable; tenants may add custom roles.
- **Relationship-based entity access.** Staff see their whole tenant via a tenant-wide read
  permission; clients see only the rows whose client legal entity they are linked to; children
  inherit from parents. A generic ACL is a deferred fallback for ad-hoc sharing.
- **Reference implementation:** a `projects` + `tasks` context in `backend/app/`, wired through
  the whole stack — the pattern new features copy.

## Three layers (keep them distinct)

1. **Authentication** — who you are (JWT → `user_id`).
2. **RBAC (role permissions)** — which *actions* your role permits, e.g. "may this user create
   a project?" Gates the endpoint.
3. **Resource access** — which specific *rows* you may act on, e.g. "may this user see project
   P?" Gates the row.

A request is authorized when all applicable layers pass: RBAC gates the endpoint; resource
access gates the row.

## Tenancy & tokens (no active tenant)

Roles, memberships, and grants are all mutable at runtime, so **nothing derived from them goes
in the JWT** — it would be stale after any edit/revoke. The token carries only `user_id`;
memberships, permissions, and visible rows are resolved per request (cache only if measured).

Because every list query already returns the cross-tenant union, there is **no
`active_tenant_id` and no `/switch-tenant`** — show the tenant name as a column in list UIs
instead. If a future feature ever needs to scope to a single tenant, pass it as an
`X-Tenant-Id` header or path segment — never bake it into the token.

## Roles & permissions

Roles are DB-driven, but the **permission catalog is a fixed code enum** — you cannot grant an
action the code never checks, so the vocabulary stays in code and is validated on write. System
roles are seeded (`tenant_id IS NULL`); tenants may clone and customize non-system roles.

One rule matters for isolation: **client roles never hold the tenant-wide read permission**
(`project:read`). A client's visibility comes solely from the relationship link below, so no
careless permission grant can leak a whole tenant.

## Resource access (who sees what)

A user reaches a project through one of two paths, unioned in a single query:

1. **Staff — tenant-wide via RBAC.** A role holding the tenant-wide `project:read` permission
   sees **all** projects in that tenant (and their tasks).
2. **Client — via a relationship link.** A project belongs to exactly one client legal entity
   (`projects.client_id`); a user linked to that entity (`legal_entity_users`) sees the project
   and its tasks.

Both paths are backed by **real foreign keys** — integrity is guaranteed by the database, with
no orphan grants and no sweep task. Neither path scopes to a single "active" tenant, so the
result is naturally the cross-tenant union.

- **Client assignment flow:** assigning a project just sets `projects.client_id` to a legal
  entity — which needs **no user accounts yet**. When a contact is later invited and accepts, a
  link row is created and they **retroactively** see every project of that client, with zero
  per-project grant rows.
- **Metadata ≠ access.** `created_by`, `updated_by`, a future assignee are metadata; access
  decisions flow only through the two paths above, so the rule lives in one place.

## Enforcement convention (declarative and hard to forget)

- `Authenticated` extractor → `user_id`.
- `AuthContext` extractor → resolves the request's memberships + permission set (across tenants);
  exposes `has(Permission)` for guards.
- `RequirePermission(perm)` guard → RBAC check on **mutating** routes, e.g.
  `.route_layer(require(Permission::ProjectWrite))`. Read routes stay open to members and rely
  on row scoping.
- `authorize_resource(user_id, entity, id)` → single-entity visibility check; returns **404** on
  failure per [conventions.md](../api/conventions.md) §6 (don't reveal existence).

Row scoping is centralized in **one** predicate/helper so new endpoints inherit it instead of
re-deriving ownership ad hoc.

## Deferred: generic ACL fallback

The `client_id` + `legal_entity_users` model covers relationship access — "everything belonging
to this client." It does **not** cover ad-hoc per-user sharing: granting *one specific entity*
to *one specific user* who is neither staff nor linked to the client (e.g. an external auditor),
optionally at different levels. If a feature ever needs that, add a generic ACL then — not
before:

- `object_access (id, tenant_id, object_type, object_id, user_id, relation, created_at)`,
  `UNIQUE(user_id, object_type, object_id)`, `relation ∈ {owner, editor, viewer}`,
  `object_type` from a code-side registry enum (no free strings).
- Resource access gains a third arm. Trade-off: `object_type`/`object_id` are not real FKs, so
  integrity is app-enforced (scope by `tenant_id`, delete grants with the object, periodic
  orphan sweep).

Implement only when a concrete requirement appears; the two paths above are the default.

---

# Implementation Plan

> **Temporary.** Concrete DDL, queries, performance checks, and the task list for Stage B.
> Once implemented — migrations, code, and tests being the source of truth — **delete this whole
> section**; the Architecture above is what remains.

## SQL schema

Copy into a migration. Requires `PRAGMA foreign_keys = ON;`. `tenants` and `users` already
exist — shown as comments for context; `users` is a **global** account (no `tenant_id`).

```sql
-- Existing (for context):
-- CREATE TABLE tenants (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, ...);
-- CREATE TABLE users   (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL UNIQUE, ...);

-- ---------- RBAC ----------

CREATE TABLE roles (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id  INTEGER REFERENCES tenants(id) ON DELETE CASCADE, -- NULL = seeded system role
    name       TEXT    NOT NULL,
    is_system  INTEGER NOT NULL DEFAULT 0 CHECK (is_system IN (0, 1)),
    created_at DATETIME NOT NULL,
    -- system roles are exactly the global ones; keep the two flags from contradicting
    CHECK ((is_system = 1) = (tenant_id IS NULL))
);
-- UNIQUE(tenant_id, name) does not constrain NULL tenant_id (NULLs are distinct), so use
-- two partial unique indexes to cover system vs tenant-custom roles.
CREATE UNIQUE INDEX ux_roles_system_name ON roles(name)            WHERE tenant_id IS NULL;
CREATE UNIQUE INDEX ux_roles_tenant_name ON roles(tenant_id, name) WHERE tenant_id IS NOT NULL;

CREATE TABLE role_permissions (
    role_id    INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission TEXT    NOT NULL, -- validated against the code-side Permission enum on write
    PRIMARY KEY (role_id, permission)
);

-- ---------- Membership ----------

CREATE TABLE tenant_memberships (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id)   ON DELETE CASCADE,
    tenant_id  INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    role_id    INTEGER NOT NULL REFERENCES roles(id)   ON DELETE RESTRICT,
    status     TEXT    NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
    created_at DATETIME NOT NULL,
    UNIQUE (user_id, tenant_id)
);
-- APP-ENFORCED INVARIANT: on assignment, validate role_id is a system role (roles.tenant_id
-- IS NULL) OR roles.tenant_id = tenant_memberships.tenant_id. A DB FK cannot express this
-- (system roles have a NULL tenant_id), so enforce it in the service and test it — otherwise a
-- tenant could assign another tenant's custom role. See "Application-enforced invariants" below.
CREATE INDEX idx_memberships_tenant ON tenant_memberships(tenant_id);
-- (user_id lookups are served by the UNIQUE(user_id, tenant_id) index prefix — no separate index.)

-- ---------- Legal entities (supertype) + subtypes ----------

CREATE TABLE legal_entities (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id     INTEGER  NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    type          TEXT     NOT NULL CHECK (type IN ('person', 'company')),
    status        TEXT     NOT NULL CHECK (status IN ('active', 'inactive')),
    country       TEXT,
    county        TEXT,
    city          TEXT,
    street_name   TEXT,
    street_number TEXT,
    postal_code   TEXT,
    iban          TEXT,
    bank_name     TEXT,
    phone         TEXT,
    email         TEXT,
    created_at    DATETIME NOT NULL,
    created_by    INTEGER  NOT NULL REFERENCES users(id) ON DELETE NO ACTION,
    updated_at    DATETIME NOT NULL,
    updated_by    INTEGER  NOT NULL REFERENCES users(id) ON DELETE NO ACTION,
    UNIQUE (tenant_id, id),        -- backs projects.(tenant_id, client_id) FK; also serves tenant_id lookups
    UNIQUE (tenant_id, id, type)   -- backs the typed subtype FKs below
);
-- no separate tenant_id index: UNIQUE(tenant_id, id) already covers tenant_id lookups by prefix.

-- The `type` column on subtypes is CHECK-pinned and part of the FK, so a subtype row can only
-- attach to a parent of the matching type. This makes company/person mutually exclusive for a
-- given entity. Presence (every 'company' has a companies row) stays app-enforced: insert the
-- supertype and its subtype in one transaction.
CREATE TABLE companies (
    id                  INTEGER PRIMARY KEY,
    tenant_id           INTEGER NOT NULL,
    type                TEXT    NOT NULL DEFAULT 'company' CHECK (type = 'company'),
    name                TEXT    NOT NULL,
    admin_name          TEXT,
    registration_number TEXT    NOT NULL,
    tax_id              TEXT    NOT NULL,
    FOREIGN KEY (tenant_id, id, type)
        REFERENCES legal_entities(tenant_id, id, type) ON DELETE CASCADE
);
-- tenant_id lookups are covered by ux_companies_name(tenant_id, name) by prefix.
CREATE UNIQUE INDEX ux_companies_name       ON companies(tenant_id, name);
CREATE UNIQUE INDEX ux_companies_tax_id     ON companies(tenant_id, tax_id);
CREATE UNIQUE INDEX ux_companies_reg_number ON companies(tenant_id, registration_number);

CREATE TABLE persons (
    id          INTEGER PRIMARY KEY,
    tenant_id   INTEGER NOT NULL,
    type        TEXT    NOT NULL DEFAULT 'person' CHECK (type = 'person'),
    first_name  TEXT,
    last_name   TEXT,
    national_id TEXT,
    details     TEXT CHECK (details IS NULL OR json_valid(details)),
    FOREIGN KEY (tenant_id, id, type)
        REFERENCES legal_entities(tenant_id, id, type) ON DELETE CASCADE
);
CREATE INDEX idx_persons_tenant ON persons(tenant_id);

-- ---------- Client access link (user <-> legal entity, M2M) ----------

CREATE TABLE legal_entity_users (
    tenant_id       INTEGER  NOT NULL,
    legal_entity_id INTEGER  NOT NULL,
    user_id         INTEGER  NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at      DATETIME NOT NULL,
    PRIMARY KEY (legal_entity_id, user_id),
    FOREIGN KEY (tenant_id, legal_entity_id)
        REFERENCES legal_entities(tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX idx_leu_user ON legal_entity_users(user_id);

-- ---------- Projects (one client per project) + tasks ----------

CREATE TABLE projects (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id   INTEGER  NOT NULL,
    client_id   INTEGER  NOT NULL,
    name        TEXT,
    description TEXT,
    number      TEXT,
    created_at  DATETIME NOT NULL,
    created_by  INTEGER  NOT NULL REFERENCES users(id) ON DELETE NO ACTION,
    updated_at  DATETIME NOT NULL,
    updated_by  INTEGER  NOT NULL REFERENCES users(id) ON DELETE NO ACTION,
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    -- composite FK closes the cross-tenant leak: the client must be in the same tenant.
    -- NO ACTION (checked at end-of-statement) still blocks deleting a legal entity that has
    -- projects, but lets a tenant-level cascade tear both down without an ordering error that
    -- ON DELETE RESTRICT (checked immediately) would raise.
    FOREIGN KEY (tenant_id, client_id)
        REFERENCES legal_entities(tenant_id, id) ON DELETE NO ACTION
);
-- tenant_id lookups covered by UNIQUE(tenant_id, id) / idx_projects_tenant_client by prefix.
CREATE INDEX idx_projects_tenant_client ON projects(tenant_id, client_id);

CREATE TABLE tasks (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id  INTEGER  NOT NULL,
    project_id INTEGER  NOT NULL,
    title      TEXT     NOT NULL,
    status     TEXT     NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'done')),
    created_at DATETIME NOT NULL,
    created_by INTEGER  NOT NULL REFERENCES users(id) ON DELETE NO ACTION,
    updated_at DATETIME NOT NULL,
    updated_by INTEGER  NOT NULL REFERENCES users(id) ON DELETE NO ACTION,
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, project_id)
        REFERENCES projects(tenant_id, id) ON DELETE CASCADE
);
-- lead with project_id so the task-visibility query (WHERE project_id IN (...)) uses the index.
CREATE INDEX idx_tasks_project ON tasks(project_id);

-- ---------- Invitations ----------

CREATE TABLE invitations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id       INTEGER  NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email           TEXT     NOT NULL,
    role_id         INTEGER  NOT NULL REFERENCES roles(id) ON DELETE RESTRICT,
    legal_entity_id INTEGER,           -- set for client invites: which client the user joins
    token_hash      TEXT     NOT NULL,
    invited_by      INTEGER  NOT NULL REFERENCES users(id) ON DELETE NO ACTION,
    expires_at      DATETIME NOT NULL,
    accepted_at     DATETIME,
    created_at      DATETIME NOT NULL,
    -- NULL legal_entity_id disables this composite FK (staff invites), which is intended.
    FOREIGN KEY (tenant_id, legal_entity_id)
        REFERENCES legal_entities(tenant_id, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX ux_invitations_token   ON invitations(token_hash);           -- single-use lookup
CREATE UNIQUE INDEX ux_invitations_pending ON invitations(tenant_id, email)
    WHERE accepted_at IS NULL;                                                    -- one open invite/email
CREATE INDEX        idx_invitations_email  ON invitations(tenant_id, email);
```

Single-use, short-lived, **hashed** invitation token (reuse the refresh-token storage
patterns). Accepting, in one transaction: create/find the `users` row, insert the
`tenant_memberships` row with `role_id`, and — for client invites — the `legal_entity_users`
row. Requires the mailer abstraction.

## Permission catalog & system roles

`role_permissions.permission` is validated against this fixed Rust enum on write (reject unknown
actions):

```
project:read      -- tenant-wide project visibility (STAFF only; consumed by the access view)
project:write     -- create/update projects
project:delete
task:write        -- create/update tasks (row-scoped to visible projects)
task:delete       -- (task READ has no permission: it inherits project visibility via the view)
entity:read       -- view legal_entities / companies / persons
entity:write      -- create/update legal entities
member:invite     -- invite internal staff into the tenant
member:remove
role:manage       -- create/edit roles and their permissions
client_user:invite-- invite a login into a client legal entity (client_admin, scoped to own)
client_user:remove
tenant:manage     -- tenant settings
billing:manage    -- billing
```

Initial system roles (seeded, `tenant_id IS NULL`, `is_system = 1`):

| Role | Kind | Permissions |
| --- | --- | --- |
| `owner` | staff | all of the above |
| `admin` | staff | everything except `billing:manage`, `tenant:manage` |
| `member` | staff | `project:read`, `project:write`, `task:write`, `entity:read/write` |
| `viewer` | staff | `project:read`, `entity:read` |
| `client_admin` | client | `task:write`, `entity:read`, `client_user:invite`, `client_user:remove` |
| `client_member` | client | `task:write` |

Client roles hold **no** `project:read` — the only tenant-wide visibility grant — so their read
access comes *solely* from `legal_entity_users` via the access view, scoped to their own
client's projects (and those projects' tasks by inheritance). `task:write` is an action guard;
the view still restricts *which* tasks they can touch. Tenants may clone and customize any
non-system role.

## Access views & queries

Row visibility lives in **one place** — a per-entity view keyed to expose `user_id`, so every
query binds only `:uid`.

```sql
CREATE VIEW project_access (project_id, tenant_id, user_id, access_level) AS
    -- staff: tenant-wide read via role permission
    SELECT p.id, p.tenant_id, m.user_id, 'staff'
    FROM tenant_memberships m
    JOIN role_permissions   rp ON rp.role_id = m.role_id AND rp.permission = 'project:read'
    JOIN projects           p  ON p.tenant_id = m.tenant_id
    WHERE m.status = 'active'
    UNION
    -- client: user linked to the project's client legal entity
    SELECT p.id, p.tenant_id, leu.user_id, 'client'
    FROM legal_entity_users leu
    JOIN projects           p  ON p.tenant_id = leu.tenant_id
                              AND p.client_id = leu.legal_entity_id;
```

Bind only `:uid`; `UNION` dedups a user who matches both paths for the same project:

```sql
-- list visible projects (cross-tenant union)
SELECT p.*
FROM projects p
WHERE p.id IN (SELECT project_id FROM project_access WHERE user_id = :uid);

-- authorize a single project (row exists AND is visible) -> 404 on empty
SELECT 1 FROM project_access WHERE project_id = :id AND user_id = :uid;

-- tasks inherit visibility from their project
SELECT t.*
FROM tasks t
WHERE t.project_id IN (SELECT project_id FROM project_access WHERE user_id = :uid);
```

Use the `IN (...)` **semi-join**, not `JOIN project_access` — the latter would duplicate a
project row when a user matches both `access_level`s. If you need the level, wrap with
`MAX(access_level)` grouped by `project_id`.

## Performance & EXPLAIN QUERY PLAN

The design is index-driven; verify it stays that way. First enable stats:

```sql
PRAGMA foreign_keys = ON;
ANALYZE;   -- give the planner row-count stats so it drives from the small side
```

Then inspect the hot query:

```sql
EXPLAIN QUERY PLAN
SELECT p.* FROM projects p
WHERE p.id IN (SELECT project_id FROM project_access WHERE user_id = 123);
```

What to require in the plan (no full `SCAN` of `projects`, `tasks`, or `legal_entities`):

- Outer: `SEARCH projects USING INTEGER PRIMARY KEY (rowid=?)` — driven by the `IN` list.
- Staff arm: `SEARCH tenant_memberships USING INDEX ...(user_id=?)` (the
  `UNIQUE(user_id, tenant_id)` index) → `SEARCH role_permissions USING PRIMARY KEY
  (role_id=? AND permission=?)` → `SEARCH projects USING INDEX idx_projects_tenant_client`
  (or the `UNIQUE(tenant_id, id)` index) `(tenant_id=?)`.
- Client arm: `SEARCH legal_entity_users USING INDEX idx_leu_user (user_id=?)` →
  `SEARCH projects USING INDEX idx_projects_tenant_client (tenant_id=? AND client_id=?)`.

Both arms start from `user_id = :uid` (the selective column) and reach `projects` through an
index. If you ever see `SCAN projects`, a supporting index is missing or `ANALYZE` was not run.
The required indexes all exist in the schema above: the `UNIQUE(user_id, tenant_id)` membership
index, `role_permissions` PK, `idx_leu_user`, and `idx_projects_tenant_client`.

**Caveat — `UNION` view materialization.** SQLite pushes `user_id = :uid` into both `UNION`
arms, but a dedup `UNION` view can be materialized into a transient b-tree rather than flattened.
Confirm in the plan that neither arm shows `SCAN projects`; if it does, drop the view and inline
the two paths as `WHERE EXISTS (...) OR EXISTS (...)` keyed on `:uid` in the query itself.

## Application-enforced invariants (the DB can't express these)

Enforce in the service layer and cover each with a test:

1. **Role belongs to the tenant.** When assigning `tenant_memberships.role_id`, require the role
   to be a system role (`roles.tenant_id IS NULL`) or `roles.tenant_id = membership.tenant_id`.
   No FK can enforce this because system roles have a NULL `tenant_id`. Without it, a tenant can
   assign another tenant's custom role — a cross-tenant permission leak.
2. **Subtype presence.** Every `legal_entities` row of `type='company'` has exactly one
   `companies` row (and `'person'` → `persons`). The typed FK guarantees a subtype can't attach
   to the wrong parent, but not that one *exists* — insert supertype + subtype in one transaction.
3. **Client roles never hold `project:read`.** Validate role-permission edits so a role used by
   client members can't be granted the tenant-wide read that would leak the whole tenant.
4. **Users are soft-deleted.** `created_by`/`updated_by` are `NOT NULL … ON DELETE NO ACTION`,
   so a user who ever authored a row cannot be hard-deleted. This assumes soft delete; if hard
   delete is ever required, those columns must become nullable with `ON DELETE SET NULL`.

## Schema tests (in `backend/test/`, in-memory SQLite)

Cover, at minimum: a cross-tenant `projects.client_id` is rejected; company/person mutual
exclusivity via the typed FK; a client sees exactly their client's projects (and not another
client's); staff `project:read` returns the whole tenant; deleting a tenant with projects +
legal entities succeeds (validates the `NO ACTION` choice above).
