# Authorization Design & Implementation Plan

Design for identity, multi-tenancy, roles/permissions, and entity-level access, plus the
step-by-step execution plan. Decided 2026-07-02; last revised 2026-07-11. The schema has
been verified by executing it in SQLite.

This document, together with the DDL in [authz-schema.sql](authz-schema.sql), is
self-contained: everything needed to implement the design is here.
Once implemented, the schema/query/step sections become redundant with the code and can be
deleted; the architecture sections should move to `docs/design/`.

# Goals and principles

- **Quality and architecture first.** The app is small, not deployed, and has no users. The
  goal is a clean, production-grade foundation — prefer the _right_ design over the
  backward-compatible one. Nothing in the current code is set in stone.
- **Breaking changes are free right now.** Schema, API, JWT-claim, and config changes cost
  nothing today and get more expensive with every deploy and user. Make them early.
- **Don't polish code about to be rewritten.** This plan rewrites registration, `UserInfo`,
  the users endpoint, and the `sample` feature — those get no cosmetic work before it.
- **Land small, individually green PRs.** Every step leaves `cargo -q xtask check backend`
  and `cargo -q xtask check frontend` passing. The refactor ships as ~18 reviewable PRs,
  not one branch.
- **The template stays reusable.** Svelaxum remains an open-source template; private
  business apps will be built on it and must be able to merge template improvements
  continuously, even after release. Design choices here (code boundaries, migration
  discipline, replaceable reference feature) exist to keep that merge cheap. See
  [Evolving the template and a business app in parallel](#evolving-the-template-and-a-business-app-in-parallel).
- **Future scale.** The apps built on this will grow into medium-large applications with a
  web client and a mobile client (likely a web-view mobile app). Design for that: security,
  efficiency, and scalability are not optional.

# Where the code is today

The current schema (`migrations/01_initial_schema.sql`) has `tenants`, `users`, and
`refresh_tokens`. The problems this plan fixes:

- **Tenancy is fake.** `users.tenant_id` is a single tenant per user; all self-signup and
  SSO users land in a seeded "Default" tenant (id 0) — `auth_service::register` hardcodes
  `TenantId(0)` and `login_oauth` uses `constants::db::DEFAULT_TENANT_ID_FOR_NEW_SSO_USERS`.
  At the same time `users.email` is globally `UNIQUE`, which contradicts a per-tenant user
  model — the two ideas conflict.
- **User data leaks.** `GET /api/users` (`users_api.rs::list_users`) returns every user in
  the caller's tenant — which is the shared default tenant — to any authenticated caller,
  with no permission gate.
- **Admin identity is a hack.** The frontend derives `isAdmin` from `user?.id === 0`
  (`frontend/src/AppState.svelte.ts`), i.e. from the seeded system user's id; there is no
  real role model anywhere. The system user (id 0, in a seeded "System" tenant, id 1) gets
  its credentials set via `backend/cli.rs` (`create_admin`, `bootstrap_admin_from_env`).
- **Registration skips onboarding.** Self-signup sets `status = 'active'` directly,
  bypassing the `onboarding` state the schema defines.
- **No email verification.** Registration never verifies the address, and
  `users_db::link_sso_user` auto-links SSO logins to an existing account via
  `INSERT ... ON CONFLICT (email) DO UPDATE` — an attacker who registers a victim's email
  first can capture their later SSO sign-in, and vice versa (account pre-hijacking).
- **No password reset, no mailer.** There is no way to send any email.
- **JWT carries `tenant_id` and `email`** (`jwt::TokenClaims`). Anything derived from
  mutable data goes stale in a token; the claims must shrink to `user_id`.
- **`refresh_tokens` is keyed by `(tenant_id, user_id)`** and every query in `tokens_db.rs`
  threads `tenant_id`. This follows the fake tenancy and must be re-keyed by `user_id`.
- **The `sample` feature is a placeholder** (`backend/app/sample/sample_api.rs`) and its
  utoipa path is declared as `/api/sample` inside a router nested under `/api`, so it ships
  as `/api/api/sample` in the OpenAPI spec and generated client.
- **Multi-write flows are not transactional** — and cannot be: every repository method
  takes `&db::Context` (the pool) directly, so services have no way to compose writes into
  one transaction. New flows in this plan (signup, invite acceptance, entity creation) are
  written transactionally from the start.

# Architecture

## The model in brief

- **Global users, real multi-tenancy.** Users are global accounts linked to tenants through
  `tenant_memberships`, one role per tenant. `users.tenant_id` is dropped, which makes the
  global `UNIQUE(email)` correct. Internal staff and external client contacts are both just
  memberships; the role distinguishes them.
- **No active tenant.** The access token carries only `user_id`; queries return the
  **union** across every tenant the user belongs to. No tenant-selection step, no
  per-tenant token re-issue.
- **DB-driven roles, code-defined permission catalog.** The set of checkable actions is a
  fixed Rust enum; only the role→permission groupings live in the DB. System roles are
  seeded and immutable; tenants may add custom roles.
- **Relationship-based entity access.** Staff see their whole tenant via a tenant-wide
  `*:read_all` permission; clients see only the rows whose client entity they are linked
  to; children (tasks) inherit visibility from parents (projects). A generic ACL is a
  deferred fallback for ad-hoc sharing.
- **Reference implementation:** a `projects` + `tasks` feature in `backend/app/`, wired
  through the whole stack — the pattern new features copy, and explicitly **replaceable**
  by business apps built on the template.

## Three layers (keep them distinct)

1. **Authentication** — who you are (JWT → `user_id`).
2. **RBAC (role permissions)** — which _actions_ your role permits, e.g. "may this user
   create a project?" Gates the endpoint.
3. **Resource access** — which specific _rows_ you may act on, e.g. "may this user see
   project P?" Gates the row.

A request is authorized when all applicable layers pass: RBAC gates the endpoint; resource
access gates the row.

## Tenancy and tokens (no active tenant)

Roles, memberships, and grants are all mutable at runtime, so **nothing derived from them
goes in the JWT** — it would be stale after any edit or revoke. The token carries only
`user_id`; memberships, permissions, and visible rows are resolved per request (add caching
only if measured).

Because every list query already returns the cross-tenant union, there is **no
`active_tenant_id` and no `/switch-tenant`** — show the tenant name as a column in list UIs
instead. If a future feature ever needs to scope a request to a single tenant, pass it as
an `X-Tenant-Id` header or a path segment — never bake it into the token.

## Roles and permissions

Roles are DB-driven, but the **permission catalog is a fixed code enum** — you cannot grant
an action the code never checks, so the vocabulary stays in code and is validated on every
write to `role_permissions`. System roles are seeded with `tenant_id IS NULL` and are
immutable; tenants may clone and customize non-system roles.

Every role has a `kind` — `staff` or `client` — fixed at creation (custom roles inherit the
kind of the role they clone). One rule matters for isolation: **client-kind roles never
hold a tenant-wide `*:read_all` permission**. A client's visibility comes solely from the
relationship link below, so no careless permission grant can leak a whole tenant.

A membership carries exactly **one role**. Permission combinations are served by cloning
a custom role that holds the union — this keeps "what can this user do in this tenant" a
single row and the role picker a dropdown. If real composition pressure ever appears, the
escape hatch is additive (a `membership_roles` M2M; permissions become the union across
roles) and changes nothing else in this design.

## Resource access (who sees what)

A user reaches a project through one of two paths, unioned in a single query:

1. **Staff — tenant-wide via RBAC.** A role holding the tenant-wide `project:read_all`
   permission sees **all** projects in that tenant (and their tasks).
2. **Client — via a relationship link.** A project belongs to exactly one client entity
   (`projects.client_id`); a user linked to that entity via `entity_users` sees the
   project and its tasks.

Both paths are backed by **real foreign keys** — integrity is guaranteed by the database,
with no orphan grants and no cleanup task. Neither path scopes to a single "active" tenant,
so the result is naturally the cross-tenant union.

- **Client assignment flow:** assigning a project just sets `projects.client_id` to an
  entity — which needs **no user accounts yet**. When a contact is later invited and
  accepts, an `entity_users` row is created and they **retroactively** see every project
  of that client, with zero per-project grant rows.
- **Metadata ≠ access.** `created_by`, `updated_by`, a future assignee are metadata; access
  decisions flow only through the two paths above, so the rule lives in one place.

## Enforcement convention (declarative and hard to forget)

Four building blocks, applied in a fixed order on every request. Each authorization rule
has exactly one home, and mutating routes visibly declare their gate at registration —
that is what makes forgetting a check hard.

**1. `Authenticated` extractor → `user_id`.** Today: `jwt::TokenClaims` inserted into
request extensions by `auth_middleware` in `backend/router.rs`. Nothing else comes from
the token.

**2. `AuthContext` extractor → the caller's capabilities.** One query per request resolves
the active memberships and the permission set each membership's role grants. Handlers and
services receive it as a regular extractor argument:

```rust
pub struct AuthContext {
    pub user_id: UserId,
    // one entry per active membership: tenant -> permissions granted by the role there
    memberships: HashMap<TenantId, HashSet<Permission>>,
}

impl AuthContext {
    // coarse: does ANY membership grant this? (route guards, where the target
    // tenant is not known yet)
    pub fn has_any(&self, perm: Permission) -> bool { /* ... */ }
    // authoritative: does the membership in THIS tenant grant it?
    pub fn has_in(&self, tenant_id: TenantId, perm: Permission) -> bool { /* ... */ }
}
```

**3. `require(permission)` route guard on mutating routes.** Declared where routes are
registered, so a reviewer sees RBAC coverage in one screen:

```rust
Router::new()
    // reads have no RBAC gate: any member may call them, row scoping does the work
    .route("/projects", get(list_projects))
    .route("/projects/{id}", get(get_project))
    // mutations declare their permission at the route
    .route("/projects", post(create_project)
        .route_layer(require(Permission::ProjectWrite)))
    .route("/projects/{id}", delete(delete_project)
        .route_layer(require(Permission::ProjectDelete)))
```

The guard is a coarse pre-filter: it checks `has_any` (the target tenant is only known
after the body/row is loaded) and returns **403**. The authoritative check runs in the
service against the tenant actually being written to:

```rust
// projects_service.rs
pub async fn create_project(ctx: &Context, auth: &AuthContext, cmd: CreateProject)
    -> Result<Project, Error>
{
    if !auth.has_in(cmd.tenant_id, Permission::ProjectWrite) {
        return Err(Error::Forbidden);
    }
    // ... insert
}
```

**4. `authorize_resource` on single-row endpoints.** One query against the entity's access
view; failure maps to **404**, not 403, per `docs/api/conventions.md` §6 (don't reveal
existence):

```rust
// projects_db.rs — LIMIT 1 because a dual-path user yields two rows under UNION ALL
pub async fn authorize_project(db: impl SqliteExecutor<'_>, user_id: UserId, id: ProjectId)
    -> Result<Option<()>, sqlx::Error>
{
    sqlx::query_scalar!(
        "SELECT 1 FROM project_access WHERE project_id = ? AND user_id = ? LIMIT 1",
        id.0, user_id.0)
        .fetch_optional(db).await.map(|r| r.map(|_| ()))
}

// in the service/handler:
authorize_project(&ctx.db, auth.user_id, id).await?.ok_or_else(api::Error::not_found)?;
```

Putting it together, per endpoint kind:

| Endpoint kind             | RBAC gate                                    | Row check                            |
| ------------------------- | -------------------------------------------- | ------------------------------------ |
| list (`GET` collection)   | none — membership implied                    | semi-join on the access view         |
| get one (`GET /{id}`)     | none                                         | `authorize_resource` → 404           |
| create (`POST`)           | `require(...)` route + `has_in` in service   | n/a (parent checked if nested)       |
| update/delete on a row    | `require(...)` route + `has_in` in service   | `authorize_resource` **first** → 404 |

For mutations on an existing row, run `authorize_resource` before `has_in`: an invisible
row must yield 404, not 403 (403 would confirm the row exists).

Row scoping is centralized in **one** predicate per entity (the access view below) so new
endpoints inherit it instead of re-deriving ownership ad hoc — list/get queries are
written only against the view, never against the raw table.

## Deferred: generic ACL fallback

The `client_id` + `entity_users` model covers relationship access — "everything
belonging to this client." It does **not** cover ad-hoc per-user sharing: granting _one
specific object_ to _one specific user_ who is neither staff nor linked to the client
(e.g. an external auditor). If a feature ever needs that, add a generic ACL then — not
before:

- `object_access (id, tenant_id, object_type, object_id, user_id, created_at)`,
  `UNIQUE(user_id, object_type, object_id)`; a row's existence grants read access (add
  access levels only when a feature needs them); `object_type` from a code-side registry
  enum (no free strings). This is a per-row read grant, deliberately not a role: roles
  are tenant-scoped action bundles tied to a membership, and the grantee here may have
  no membership at all.
- Resource access gains a third arm in the access view. Trade-off: `object_type` /
  `object_id` are not real FKs, so integrity is app-enforced (scope by `tenant_id`, delete
  grants with the object, periodic orphan sweep).

Implement only when a concrete requirement appears; the two paths above are the default.

# Target schema

The complete DDL — tables, indexes, the `updated_at` and invariant triggers, and the
`project_access` view — lives in [authz-schema.sql](authz-schema.sql) next to this
document. It requires `PRAGMA foreign_keys = ON;` and has been verified by executing it
in SQLite, including the constraint/trigger failure cases and the query plans below.
`tenants` and `users` already exist; `users` becomes a **global** account (no
`tenant_id`).

While the template is unreleased, the platform part of the DDL lands directly in the
initial schema migration (rewritten in place; dev databases are recreated with
`cargo xtask sqlx reset`). Only the replaceable reference feature (`projects`, `tasks`,
`project_access`) gets a migration of its own, in the app stream (see
[Schema evolution](#schema-evolution-two-migration-streams)). After the first release,
schema changes switch to append-only migrations.

Invitation tokens are single-use, short-lived, and stored **hashed** (reuse the
refresh-token storage pattern). Accepting an invite runs in one transaction: create/find
the `users` row, insert the `tenant_memberships` row with `role_id`, and — for client
invites — the `entity_users` row. Requires the mailer abstraction.

# Permission catalog and system roles

`role_permissions.permission` is validated against this fixed Rust enum on write (unknown
actions are rejected):

```
project:read_all  -- see every project of the tenant (STAFF only; consumed by the access view)
project:write     -- create/update projects
project:delete
task:write        -- create/update tasks (row-scoped to visible projects)
task:delete       -- (task READ has no permission: it inherits project visibility via the view)
entity:read_all   -- see every entity (companies / persons) of the tenant (STAFF only)
entity:write      -- create/update entities
entity:delete
member:invite     -- invite internal staff into the tenant
member:remove
role:manage       -- create/edit roles and their permissions
client_user:invite-- invite a login into a client entity (client_admin, scoped to own)
client_user:remove
tenant:manage     -- tenant settings
billing:manage    -- billing
```

The `*:read_all` suffix marks a **tenant-wide row-visibility grant** — the only kind of
permission that widens what a user can _see_. Plain reads carry no permission at all: any
member may call read endpoints, and row scoping (the access view, tenant membership)
decides what comes back. So a role can never hold a "read" that means more than it says.

Initial system roles (seeded with `tenant_id IS NULL` — which is what makes a role a
system role; "Kind" is the `roles.kind` column):

| Role            | Kind   | Permissions                                                                        |
| --------------- | ------ | ---------------------------------------------------------------------------------- |
| `owner`         | staff  | all of the above                                                                   |
| `admin`         | staff  | everything except `billing:manage`, `tenant:manage`                                |
| `member`        | staff  | `project:read_all`, `project:write`, `task:write`, `entity:read_all`, `entity:write` |
| `viewer`        | staff  | `project:read_all`, `entity:read_all`                                              |
| `client_admin`  | client | `task:write`, `client_user:invite`, `client_user:remove`                           |
| `client_member` | client | `task:write`                                                                       |

Client-kind roles hold **no** `*:read_all` permission — the tenant-wide visibility
grants — so their read access comes _solely_ from `entity_users` via the access view,
scoped to their own client's projects (and those projects' tasks by inheritance).
`task:write` is an action guard; the view still restricts _which_ tasks they can touch.
A client's view of their own entity record (a future profile page) would be a dedicated
`entity_users`-scoped endpoint, never `entity:read_all`. Tenants may clone and customize
any non-system role; the clone keeps the original's `kind`.

# Access view and queries

Row visibility lives in **one place** — a per-entity view keyed to expose `user_id`, so
every query binds only `:uid`. The `project_access` view (DDL and the `UNION ALL`
rationale in [authz-schema.sql](authz-schema.sql)) exposes
`(project_id, tenant_id, user_id, access_level)` with one arm per access path: staff via
the `project:read_all` role permission, client via the `entity_users` link. Note it must
stay `UNION ALL`, not `UNION` — see the performance section below.

Bind only `:uid`:

```sql
-- list visible projects (cross-tenant union)
SELECT p.*
FROM projects p
WHERE p.id IN (SELECT project_id FROM project_access WHERE user_id = :uid);

-- authorize a single project (row exists AND is visible) -> 404 on empty.
-- LIMIT 1 because a dual-path user yields two rows under UNION ALL.
SELECT 1 FROM project_access WHERE project_id = :id AND user_id = :uid LIMIT 1;

-- tasks inherit visibility from their project
SELECT t.*
FROM tasks t
WHERE t.project_id IN (SELECT project_id FROM project_access WHERE user_id = :uid);
```

Use the `IN (...)` **semi-join**, not `JOIN project_access` — with `UNION ALL` the view
yields one row per access path, so a join would duplicate a project row for a user who
matches both. If you need the level, aggregate: `MAX(access_level)` grouped by
`project_id` (`'staff' > 'client'` alphabetically, conveniently).

# Performance checks (EXPLAIN QUERY PLAN)

The design is index-driven; verify it stays that way. The plans below were verified by
executing this schema in SQLite 3.40 with a synthetic dataset of 200 tenants / 5000
users / 8000 legal entities / 20 000 projects. First enable stats:

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

What to require in the plan — no full `SCAN` of `projects`, `tenant_memberships`, or
`entity_users`:

- Outer: `SEARCH p USING INTEGER PRIMARY KEY (rowid=?)` — driven by the `IN` list.
- Staff arm: `SEARCH m USING INDEX ...(user_id=?)` (the `UNIQUE(user_id, tenant_id)`
  membership index) joined with `role_permissions` (PK search, or a `SCAN rp` — that
  table is tiny, bounded by roles × catalog size, and the planner may pick either) →
  `SEARCH p USING COVERING INDEX idx_projects_tenant_client (tenant_id=?)`.
- Client arm: `SEARCH eu USING INDEX idx_entity_users_user (user_id=?)` →
  `SEARCH p USING COVERING INDEX idx_projects_tenant_client (tenant_id=? AND client_id=?)`.

Both arms start from `user_id = :uid` (the selective column) and reach `projects` through
an index. The required indexes all exist in the schema: the `UNIQUE(user_id, tenant_id)`
membership index, the `role_permissions` PK, `idx_entity_users_user`, and
`idx_projects_tenant_client`.

**Why the view must be `UNION ALL`.** With a deduplicating `UNION`, SQLite does **not**
push `user_id = :uid` into the arms: the whole view — the access pairs of _every user in
the database_ — is materialized into a transient b-tree on every query, including the
single-row `authorize_resource` check. Measured on the dataset above: 116 ms vs 0.1 ms
per query (~1000×), and the cost scales with total data instead of the caller's visible
set. `UNION ALL` restores push-down and produces exactly the plans listed above. Keep an
`EXPLAIN QUERY PLAN` assertion in the reference-feature tests (step 8) so a future edit
cannot silently reintroduce the materialization.

# Invariants beyond foreign keys

Plain FKs cannot express these; each has its own enforcement point and a test:

1. **Role belongs to the tenant.** `tenant_memberships.role_id` must be a system role
   (`roles.tenant_id IS NULL`) or a role of the membership's own tenant — otherwise a
   tenant could assign another tenant's custom role, a cross-tenant permission leak. No
   FK can express the OR, so the schema enforces it with `BEFORE INSERT/UPDATE` triggers
   on `tenant_memberships` (`trg_memberships_role_tenant_*` in `authz-schema.sql`); the
   service validates it too, for a friendly error. Invitations validate the role's tenant
   at creation; the membership trigger backstops acceptance.
2. **Subtype presence** (service-enforced). Every `entities` row of `type='company'` has
   exactly one `companies` row (and `'person'` → `persons`). The typed FK guarantees a
   subtype can't attach to the wrong parent, but not that one _exists_ — insert supertype
   + subtype in one transaction.
3. **Client-kind roles never hold a `*:read_all` permission** (service-enforced).
   Validate role-permission edits against `roles.kind` so no role of kind `client` can be
   granted the tenant-wide visibility that would leak the whole tenant. Client
   invitations must reference client-kind roles only.
4. **Users are soft-deleted.** `created_by`/`updated_by` are `NOT NULL … ON DELETE NO
ACTION`, so a user who ever authored a row cannot be hard-deleted. This assumes soft
   delete; if hard delete is ever required, those columns must become nullable with
   `ON DELETE SET NULL`.

# Schema tests

In `backend/test/`, against in-memory SQLite (`common::Context::create_test_context()`
already provides one). Cover, at minimum:

- a cross-tenant `projects.client_id` is rejected by the composite FK;
- company/person mutual exclusivity via the typed FK;
- assigning another tenant's custom role is rejected by the membership triggers (on both
  insert and update);
- a client sees exactly their client's projects (and not another client's);
- staff with `project:read_all` sees the whole tenant;
- a user matching both access paths (staff + client-linked) still gets each project
  exactly once through the semi-join queries;
- deleting a tenant with projects + entities succeeds (validates the `NO ACTION` choice
  on `projects.client_id`);
- each service-enforced invariant above has a test that fails before the service check
  exists.

# Execution plan

Eighteen steps, each an individually reviewable PR that leaves all checks green. Steps state
their dependencies; anything not listed as a dependency can be reordered or parallelized.

Mechanics that apply to **every** step (from the current codebase):

- The module tree is declared in `backend/main.rs` — every new source file (including test
  files under the `mod test` block) must be registered there.
- Services are constructed and routers merged in `backend/router.rs::create()`.
  Authenticated routes sit behind `auth_middleware`, which decodes the
  `__Host-access_token` cookie and inserts `jwt::TokenClaims` into request extensions
  (the matching extractor lives at the bottom of `backend/platform/shared/api.rs`).
- Schema changes: while unreleased, edit the initial schema migration in place (today
  `migrations/01_initial_schema.sql`; under `migrations/platform/` once step 18 lands —
  the reference feature is excepted and lives in the app stream), then
  `cargo xtask sqlx reset` (recreates the dev DB) and `cargo xtask sqlx prepare`
  (regenerates the offline query data that pre-push checks).
- New/changed endpoints: annotate with utoipa, run `cargo xtask make openapi` to
  regenerate `openapi.json` and `frontend/src/lib/generated/`; frontend calls only the
  generated client (`api.…` from `$lib/generated/endpoints.ts`).
- New code gets new tests, including a test that fails before the fix (when fixing something);
  API error responses follow `docs/api/conventions.md` and the `api::Error` constructors in
  `backend/platform/shared/api.rs`.
- Finish with `cargo -q xtask check backend` and (when the client changed)
  `cargo -q xtask check frontend`.

### Step 1 — Permission catalog ([#208](https://github.com/AndreiBozantan/svelte-axum-template/issues/208))

Depends on: nothing.

- New file `backend/platform/shared/permissions.rs` (register `pub mod permissions;` in
  the `shared` block of `main.rs`): `pub enum Permission` with one variant per catalog
  entry, stable string forms via `Display`/`FromStr` (`Permission::ProjectReadAll` ↔
  `"project:read_all"`), and an exhaustive `ALL` list for seeding/validation.
- Also add `RoleKind { Staff, Client }` with string forms, for later steps.
- Tests in `backend/test/platform/shared/permissions_tests.rs`: every variant round-trips;
  unknown strings are rejected.

Done when: enum + tests merged; nothing else uses it yet.

### Step 2 — Global user accounts ([#209](https://github.com/AndreiBozantan/svelte-axum-template/issues/209) part 1, [#215](https://github.com/AndreiBozantan/svelte-axum-template/issues/215))

Depends on: nothing. The schema change and the JWT-claim change are one step because
`tenant_id` threads from the claims into every DB query — they cannot land separately and
stay green.

- Rewrite `migrations/01_initial_schema.sql`: `users` loses `tenant_id` (and the
  `UNIQUE(tenant_id, id)` / tenant FK); `refresh_tokens` loses `tenant_id` (FK becomes
  `user_id REFERENCES users(id) ON DELETE CASCADE`, index on `user_id`). Keep the
  "System" tenant (id 1) and system user (id 0) seeds; **drop** the "Default" tenant
  (id 0) seed.
- `backend/platform/shared/jwt.rs`: remove `tenant_id` and `email` from `TokenClaims`
  (and the `tenant_id()` helper); `generate_token()` loses the `tenant_id`/`email`
  parameters. Update `backend/test/platform/shared/jwt_tests.rs`.
- `backend/platform/identity/users/`: `User`, `CreateUserCommand`, `LinkSsoUserCommand`,
  `ListUsersQuery` lose `tenant_id` (`users_service.rs`); every query in `users_db.rs`
  drops its `tenant_id` predicate (`find_by_id`, `update_password_hash`,
  `update_failed_login_count`, `reset_failed_login_count`, `create_user`,
  `link_sso_user`, `list_by_tenant` — temporarily a global list; it is reworked in
  step 14).
- `backend/platform/identity/tokens/`: `CreateRefreshTokenCommand` loses `tenant_id`;
  `tokens_db.rs` queries key on `jti`/`user_id` only.
- `backend/platform/identity/auth/auth_service.rs`: drop `TenantId(0)` in `register`,
  the `DEFAULT_TENANT_ID_FOR_NEW_SSO_USERS` use in `login_oauth` (delete the constant
  from `constants.rs`), and all tenant threading in `login` / `refresh` /
  `revoke_refresh_token` / `handle_revoked_token_refresh` /
  `generate_access_token` / `generate_refresh_token`.
- `users_api.rs`: `UserInfo` loses `tenant_id`; `list_users` / `user_info` stop reading
  tenant claims. `backend/cli.rs` (`create_admin`, `bootstrap_admin_from_env`) still
  works — it keys on user id only.
- Regenerate openapi + client; fix any frontend fallout (`UserInfo.tenant_id` is unused
  in frontend code today).

Done when: no token contains tenant or email data; grep for `tenant_id` finds no hits in
`jwt.rs`/`tokens_db.rs`/`users_db.rs`; all existing tests pass on the new schema.

### Step 3 — RBAC schema, memberships, seeds ([#209](https://github.com/AndreiBozantan/svelte-axum-template/issues/209) part 2)

Depends on: steps 1–2.

- Extend `migrations/01_initial_schema.sql` with `roles`, `role_permissions`,
  `tenant_memberships` and the invariant-1 triggers (DDL in `authz-schema.sql`); seed the
  six system roles with their `kind` and permissions, and an `owner` membership for the
  system user (user 0 → tenant 1).
- New sub-feature `backend/platform/identity/memberships/` (`memberships_db.rs`,
  `memberships_service.rs`, tests) following the `users/` file pattern; `RoleId` newtype
  in `backend/platform/shared/common.rs` next to `UserId`/`TenantId`.
- Service functions: `create_membership` / `assign_role` validating invariant 1 (role is
  a system role or belongs to the same tenant) for friendly errors — the DB triggers
  backstop it; test both layers. Writes to `role_permissions` validate strings via
  `Permission::from_str`.
- No endpoints yet; wire only the service and tests.

Done when: seeds are queryable in tests; the invariant-1 triggers and service validation
are both covered by tests.

### Step 4 — Transactional repositories

Depends on: step 2. _No GitHub issue yet — create one; it implements the "multi-write
flows are transactional as they are written" requirement._

- Generalize repository methods from `&db::Context` (the pool) to
  `impl sqlx::SqliteExecutor<'_>` (or explicit `&mut sqlx::SqliteConnection` variants) in
  `users_db.rs`, `tokens_db.rs`, `memberships_db.rs`, so services can run several writes
  inside one `context.db.begin()` transaction.
- Keep call sites passing the pool unchanged in behavior; add one test that drives a
  two-write flow where the second write fails and asserts the first rolled back.

Done when: a service can compose repository calls in a transaction; existing tests
untouched and green.

### Step 5 — Registration and SSO create real tenants ([#211](https://github.com/AndreiBozantan/svelte-axum-template/issues/211))

Depends on: steps 3–4.

- `auth_service::register`: one transaction creates the `users` row, a new `tenants` row
  (name derived from the registered name or email local-part), and an `owner` membership.
  Status handling stays as-is (`Active`) until step 12.
- `auth_service::login_oauth`: a _new_ SSO user goes through the same
  user + tenant + owner-membership transaction; an _existing_ user keeps the current
  sso-field update. (The unsafe email auto-link itself is fixed in step 11.)
- Update `backend/test/platform/identity/auth_api_tests.rs` / `auth_service_tests.rs`;
  add: signup is atomic (inject a failing write → no partial rows), signup yields an
  owner membership, SSO signup yields a tenant.

Done when: a fresh signup logs in and holds the `owner` role in its own tenant; no code
references a default tenant.

### Step 6 — Authorization machinery ([#216](https://github.com/AndreiBozantan/svelte-axum-template/issues/216))

Depends on: steps 1, 3.

- New `backend/platform/identity/auth/auth_context.rs` (or extend `auth_service.rs`):
  `AuthContext { user_id, memberships, permissions }` resolved per request by one query
  joining `tenant_memberships` × `role_permissions` (`WHERE user_id = ? AND status =
'active'`); implements `axum::extract::FromRequestParts` reading the `TokenClaims`
  extension (same pattern as the extractor in `shared/api.rs`); exposes
  `has_any(Permission)` and `has_in(TenantId, Permission)`.
- `require(Permission)` route-layer guard for mutating routes (an
  `axum::middleware::from_fn_with_state` like `auth_middleware` in `router.rs`), returning
  the new `api::Error::forbidden()` (403 constructor to add in `shared/api.rs`, code
  `"forbidden"`, per conventions.md).
- `authorize_resource` convention: a per-feature `_db` query against the feature's access
  view returning `Option<()>`, mapped to `api::Error::not_found()` (404, per
  conventions.md §6). The first real implementation lands with step 8.
- Tests: guard returns 403 without the permission and passes with it; `AuthContext`
  resolves permissions across two tenants; suspended membership resolves to no
  permissions.

Done when: extractor + guard exist with tests; one smoke route in tests uses them.

### Step 7 — Entities: schema and endpoints ([#210](https://github.com/AndreiBozantan/svelte-axum-template/issues/210))

Depends on: steps 4, 6.

- Extend `migrations/01_initial_schema.sql` with `entities`, `companies`, `persons`,
  `entity_users` (DDL in `authz-schema.sql`); `EntityId` newtype in `common.rs`.
- New bounded context `backend/platform/entities/` with `entities_api.rs`,
  `entities_db.rs`, `entities_service.rs` (+ tests in `backend/test/`), following
  `backend/platform/identity/users/` as the template; register in `main.rs`, construct
  the service and merge the router in the private section of `router.rs::create()`.
- Endpoints per conventions.md: list/get gated by `entity:read_all`, create/update by
  `entity:write`, delete by `entity:delete` via the step-6 guard; create inserts
  supertype + subtype in **one transaction** (invariant 2); single-entity get uses
  tenant-membership scoping and 404s on rows outside the caller's tenants.
- utoipa annotations, `cargo xtask make openapi`.
- Schema tests: typed-FK mutual exclusivity; cross-tenant subtype attach rejected;
  supertype-without-subtype rolls back.

Done when: entity CRUD works end-to-end through the generated client in a test; schema
tests green.

### Step 8 — Reference feature: projects + tasks, delete `sample` ([#219](https://github.com/AndreiBozantan/svelte-axum-template/issues/219))

Depends on: step 7.

- New migration for the reference feature in its **own file** (business apps drop/replace
  it; it lives in `migrations/app/` once step 18 lands): `projects`, `tasks`, and the
  `project_access` view (DDL in `authz-schema.sql`); `ProjectId`/`TaskId` newtypes.
- New feature `backend/app/projects/` with `projects_api.rs`, `projects_db.rs`,
  `projects_service.rs`, tests — the copy-me pattern. Reads use the semi-join queries
  binding `:uid`; single-row endpoints call the feature's `authorize_resource` query
  (404 on denial); mutations guarded with `require(Permission::ProjectWrite)` etc.
- Delete `backend/app/sample/` (and its `mod` in `main.rs`, its `router()` merge in
  `router.rs`, and `backend/test/app/sample/sample_tests.rs`). utoipa `path` values are
  relative to the nested router (`"/projects"`, never `"/api/..."`).
- Regenerate openapi + client; add a minimal `Projects` page in `frontend/src/pages/`
  (route in `Router.svelte.ts`) listing visible projects with a tenant-name column, via
  the generated client.
- Boundary tests: staff with `project:read_all` sees all tenant projects and their tasks; a
  client-linked user sees only their client's projects/tasks, across every tenant they
  belong to; cross-tenant access → 404; an `EXPLAIN QUERY PLAN` test asserts no
  `SCAN projects` (Performance section above).

Done when: the feature replaces `sample` end-to-end and the boundary tests pass.

### Step 9 — Role management endpoints ([#217](https://github.com/AndreiBozantan/svelte-axum-template/issues/217))

Depends on: step 6.

- New sub-feature `backend/platform/identity/roles/` (`roles_api.rs`, `roles_db.rs`,
  `roles_service.rs`, tests): list roles visible to a tenant (system + own custom),
  create custom role (clone of an existing role, inheriting `kind`), edit a custom
  role's permissions, delete an unused custom role, assign a role to a membership — all
  gated by `role:manage` in the target tenant (`has_in`).
- Validations, each with a failing-first test: system roles immutable (reject edit/delete
  of roles with `tenant_id IS NULL`); permission strings must parse via
  `Permission::from_str`;
  invariant 3 — a `kind = 'client'` role can never be granted a `*:read_all` permission;
  invariant 1 re-checked on assignment (service from step 3).

Done when: a tenant can clone/customize/assign roles; all four validations covered.

### Step 10 — Mailer abstraction ([#212](https://github.com/AndreiBozantan/svelte-axum-template/issues/212))

Depends on: nothing (parallel to steps 5–9).

- New `backend/platform/shared/mailer.rs`: `trait Mailer` (`send(EmailMessage)`), a
  console/log implementation (default in dev/test — messages become visible in test
  assertions and the dev log), and one real SMTP provider implementation (e.g. `lettre`).
- `MailerSettings` added to `AppSettings` in `backend/platform/shared/config.rs` and to
  `data/configs.*.toml` (secrets only in the git-ignored `configs.local.toml`); the
  selected implementation is stored on `common::Context` next to `http_client`.
- Tests: console mailer captures a sent message; config selects the implementation.

Done when: any service can send mail through `context`; dev/test default never touches
the network.

### Step 11 — Email verification and the SSO auto-link fix ([#213](https://github.com/AndreiBozantan/svelte-axum-template/issues/213))

Depends on: steps 4, 5, 10.

- Schema (extend `01_initial_schema.sql`): `users.email_verified_at DATETIME` and the
  shared single-use `user_tokens` table (DDL in `authz-schema.sql`).
- Shared token service (in `identity/tokens/` next to the refresh-token code, which
  already models hash-at-rest + single-use): generate → store hash → email link →
  verify-and-consume in one transaction.
- Registration sends the verification email; a public verify endpoint sets
  `email_verified_at`.
- Fix `users_db::link_sso_user`: remove the `ON CONFLICT (email) DO UPDATE` upsert.
  New logic in `auth_service::login_oauth`: match by `(sso_provider, sso_id)` first;
  if none and a user with that email exists, auto-link **only if** the local account's
  email is verified (the provider side is already checked — `oauth_service.rs` rejects
  unverified provider emails with `Error::UnverifiedEmail`); otherwise reject with a
  message directing the user to log in with their password first.
- Tests: the pre-hijack scenario (attacker registers victim's email, never verifies;
  victim's SSO login must NOT attach to the attacker's account); verification token is
  single-use and expires.

Done when: the pre-hijack test passes; registration → verify → login works end-to-end.

### Step 12 — User lifecycle ([#214](https://github.com/AndreiBozantan/svelte-axum-template/issues/214))

Depends on: step 11.

- Self-signup creates users as `onboarding`; email verification transitions to `active`.
  Invited users (step 13) start `onboarding` and activate on first login.
- Define the allowed transitions (`onboarding → active → suspended ⇄ active → archived`)
  in one service function with a test per edge; keep the checks at **both**
  token-issuing points — `auth_service::login` and `auth_service::refresh` already test
  `status != Active`; extend them to distinguish "unverified" (actionable error) from
  "suspended/archived" (generic `invalid_credentials`, no account-state oracle).
- `AuthContext` (step 6) already filters `tenant_memberships.status = 'active'` —
  membership suspension and account suspension stay independent.

Done when: non-active users get no tokens; transition tests cover every edge.

### Step 13 — Invitations ([#218](https://github.com/AndreiBozantan/svelte-axum-template/issues/218))

Depends on: steps 7, 9, 10, 12.

- Extend `01_initial_schema.sql` with `invitations` (DDL in `authz-schema.sql`).
- New sub-feature `backend/platform/identity/invitations/` (api/db/service + tests):
    - create invite: staff invites gated by `member:invite` in the target tenant; client
      invites (`entity_id` set) also allowed for callers holding
      `client_user:invite` who are themselves linked to that same entity; the role
      must be client-kind for client invites (invariant 3 corollary), and invariant 1
      applies. Sends the invite link via the mailer; token single-use + hashed via the
      step-11 pattern. Re-inviting an email that already has a pending (possibly expired)
      invite **replaces** it — delete + insert in one transaction — because
      `ux_invitations_pending` allows only one open invite per (tenant, email).
    - accept invite (public endpoint, token in body): in **one transaction** — find/create
      the `users` row (`onboarding` for new users), insert the membership, and for client
      invites the `entity_users` row; set `accepted_at`.
- Tests: staff invite; client invite grants retroactive visibility of the client's
  existing projects (the step-8 view proves it); expiry; single-use; the
  one-open-invite-per-email partial unique index; re-inviting after expiry succeeds by
  replacing the stale pending invite.

Done when: invite → email → accept → see-projects passes end-to-end.

### Step 14 — Replace `GET /api/users` with a member listing ([#220](https://github.com/AndreiBozantan/svelte-axum-template/issues/220))

Depends on: step 6.

- Delete `list_users` from `users_api.rs` (and `ListUsersQuery`/`list_by_tenant` from the
  users repo — since step 2 it lists _all_ users, unguarded; no frontend code calls it).
- Add a tenant-scoped member listing in the memberships sub-feature (step 3):
  `GET /tenants/{tenant_id}/members` returning membership + role + the user fields an
  admin UI needs, gated by `has_in(tenant, member:invite | member:remove)`; 404 for
  tenants the caller doesn't belong to (conventions.md §6).
- Regenerate openapi + client.

Done when: no endpoint discloses users outside the caller's tenants; the gate is tested.

### Step 15 — Capabilities in `UserInfo` ([#221](https://github.com/AndreiBozantan/svelte-axum-template/issues/221))

Depends on: step 6.

- Extend `UserInfo` (`users_api.rs`) with `memberships: [{ tenant_id, tenant_name, role,
permissions }]`, resolved via the `AuthContext` query. `UserInfo` is embedded in
  `LoginResponse`, `RegisterResponse`, `RefreshResponse` (`auth_api.rs`) and
  `UserInfoResponse` (`users_api.rs`), so the frontend session state gets capabilities on
  login and refresh for free.
- Frontend: replace `isAdmin = $derived(this.user?.id === 0)` in
  `frontend/src/AppState.svelte.ts` with permission-derived state (e.g.
  `hasPermission(perm)` across memberships); update the usage in `AppSidebar.svelte`;
  regenerate the client.

Done when: UI affordances derive from permissions; nothing reads magic user ids.

### Step 16 — Write `docs/design/authentication.md` ([#222](https://github.com/AndreiBozantan/svelte-axum-template/issues/222))

Depends on: steps 11–13 (documents what they built).

Capture the authentication design as it now exists, in one place:

- access/refresh token lifecycle: rotation on refresh, reuse/breach detection
  (`handle_revoked_token_refresh` revokes all user tokens beyond the
  `REFRESH_TOKEN_GRACE_PERIOD_SECONDS` grace window), hash-at-rest;
- cookie strategy: `__Host-` prefixes, `HttpOnly`, `SameSite` (see `cookies.rs`), and why
  no token material ever goes to `localStorage`;
- the signed OAuth state-cookie design (PKCE verifier + CSRF hash) — the long design
  comment in `oauth_service.rs` is verified starting material and should move here,
  leaving a pointer;
- the shared single-use hashed-token pattern (email verification, password reset,
  invitations) and the mailer abstraction;
- account lifecycle states and their enforcement points (login + refresh).

Done when: the doc exists and matches the code; the duplicated code comments shrink to
pointers.

### Step 17 — Frontend code boundaries

Depends on: nothing functionally; sequence it around steps 8 and 15, which touch the same
files. Serves the template/app merge strategy below.

- Split the route table: `Router.svelte.ts` keeps `RouterModel`, the `link` action, and
  the template pages (home, login, register, logout, settings); a new app-owned
  `frontend/src/app/routes.ts` exports the app's `PageDefinition[]` (dashboard, projects,
  about, …), which `Router.svelte.ts` concatenates into `Pages`. An app then adds or
  replaces pages without editing a template-owned file.
- `AppSidebar.svelte` already renders purely from `Pages` (`navPosition` + visibility
  rules), so it stays template-owned as-is; move the branding bits (logo glyph, app name,
  accent colors) into a small app-owned `frontend/src/app/branding.ts` consumed by the
  sidebar.
- Extend `PageDefinition` with `requiredPermission?: string` so step 15's
  permission-derived visibility stays declarative in the route list instead of leaking
  `if` checks into components.

Done when: adding an app page touches only files under `frontend/src/app/`.

### Step 18 — Two migration streams (sqlx 0.9)

Depends on: nothing functionally; landing it before step 8 lets the reference-feature
migration be created directly in the app stream. Implements the
[schema evolution](#schema-evolution-two-migration-streams) mechanics below.

- Upgrade sqlx to 0.9 (review its breaking changes; re-run `cargo xtask sqlx prepare`).
- Split `migrations/` into `migrations/platform/` (template-owned) and `migrations/app/`
  (the reference feature; app-owned after forking); switch file versions to date prefixes
  (`YYYYMMDDHHMM_name.sql`).
- Run two migrator passes at startup — platform first — each with its own history table
  via `Migrator::dangerous_set_table_name` (e.g. `_sqlx_migrations_platform`,
  `_sqlx_migrations_app`).
- Update `cargo xtask sqlx reset` / `prepare` and the git-hook checks for the new layout.
- Tests: a fresh database applies both streams in order; the app stream sees tables
  created by the platform stream.

Done when: `cargo xtask sqlx reset` recreates the dev DB from both streams; checks green.

# Evolving the template and a business app in parallel

Svelaxum stays open-source; business apps live in private repos built on it. The
requirement: **template improvements and fixes must merge into the business app
continuously, even after the app is released.**

## Repo strategy

Create the private repo as a git clone of svelaxum pushed to a private remote, and keep
svelaxum as a second remote:

```sh
git clone git@github.com:AndreiBozantan/svelaxum.git myapp && cd myapp
git remote rename origin template
git remote add origin git@github.com:<owner>/myapp.git
git push -u origin main
# later, repeatedly:
git checkout main && git fetch template && git merge template/main
```

Plain `git merge` preserves full history and three-way merge context, which keeps repeated
merges cheap. Merge **often** — small frequent merges conflict far less than rare big ones.
(Alternatives — `git subtree`, copying patches by hand, or a cookiecutter-style one-shot
template — all lose the continuous-merge property and are rejected.)

## Code boundaries (what makes merges cheap)

- **Template-owned:** `backend/platform/`, `xtask/`, the frontend shell
  (`frontend/src/lib/` core, `Router.svelte.ts`, `AppSidebar.svelte`,
  `AppState.svelte.ts`), build and CI config. The app never edits these; needed changes
  are contributed upstream to svelaxum and merged back down.
- **App-owned:** `backend/app/`, `frontend/src/app/` (app pages, route list, branding —
  see step 17), `data/configs.local.toml`. The template keeps `backend/app/` minimal
  (the reference feature only), so app code rarely collides with template changes.
- **Known contact points**, kept as small declarative lists so conflicts are trivial:
  the module tree in `backend/main.rs`, router registration in `backend/router.rs`,
  config struct fields, the app route list in `frontend/src/app/routes.ts` (step 17).
- **The reference feature is replaceable by design.** `projects` + `tasks` exist to be
  copied or deleted. The durable platform pieces are identity, tenancy, roles,
  `entities` + subtypes, `entity_users`, and the access-view _pattern_.

## Schema evolution: two migration streams

Ground rules:

- Migrations are **append-only and immutable** once applied to any database (i.e. from the
  app's first release; the template pre-release edits the initial schema migration in
  place). The app never edits or deletes a template migration file; undoing something
  means a new migration.
- The app never `ALTER`s template-owned tables. App-specific data goes into app-owned
  tables, 1:1 **extension tables** keyed by the template row's id (e.g. a
  `user_profiles(user_id, …)` table), or designated JSON columns (`persons.details`).
- Replaceable template tables (the reference feature) are dropped and re-created by an
  early **app** migration, not by editing template files.

Mechanics (set up by step 18):

- `migrations/platform/` is template-owned and merges from the template **untouched** —
  no renaming, no re-stamping, ownership visible in the file tree. `migrations/app/`
  holds the reference feature in the template and is fully app-owned after forking.
- Two migrator passes run at startup — platform first — each with its own history table.
  This requires sqlx 0.9, where `Migrator` exposes `dangerous_set_table_name()`; sqlx 0.8
  has no way to configure the history table.
- Versions are date-prefixed (`YYYYMMDDHHMM_name.sql`) in both streams.

Cross-stream ordering: platform always runs first. In the rare case an app migration must
run _between_ two platform migrations (e.g. move data out of a column before a template
migration drops it), the app may exceptionally drop a date-prefixed migration into
`migrations/platform/`. Caveat: a later merge can deliver a template migration whose
timestamp sorts before that interleaved file, and sqlx has no out-of-order mode — the
migrator then fails loudly and the interleaved file must be re-stamped. Frequent merges
keep timestamps effectively monotonic, so this stays an edge case.

(A single re-stamped migration sequence and app-owned manual schema porting were
considered and rejected: the first needs a rename ritual on every merge, the second
drifts silently and loses the continuous-merge property.)

## Guidance for apps built on the template

Drafting a real business-app schema against this design validated it and produced rules
any derived app should follow:

- **Use the platform extension points, don't alter platform tables.** Domain-specific
  person/company fields map onto the generic columns (`national_id`,
  `registration_number`) or go into extension tables / `persons.details` JSON.
- **Replace the reference feature, don't extend it.** A real app's core entity typically
  has a different shape — many domain columns and *several* entity relations on one row
  (plus M2M links), not a superset of `projects`. This is why the template keeps
  `projects`/`tasks` in their own migration: an early app migration drops them and
  creates the app's own tables and its own access view.
- **The access-view pattern generalizes.** Every relation that should grant visibility
  becomes one more view arm (e.g. contacts of each linked entity see the row) — same
  `entity_users` link, same semi-join queries, just more `UNION ALL` arms.
- **Adopt the safety patterns in app tables:** tenant-pinned composite FKs
  (`FOREIGN KEY (tenant_id, x_id) REFERENCES entities(tenant_id, id)` — a plain
  `REFERENCES entities(id)` is a cross-tenant reference leak), the typed subtype FK, and
  `created_by`/`created_at` audit columns.
- **Extension tables key off the identity model of this design:** per-user app data keys
  on `user_id` alone (there is no `users.tenant_id`); per-membership data keys on
  `tenant_memberships.id`.
