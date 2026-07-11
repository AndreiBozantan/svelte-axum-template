-- Target schema for the authorization design — see authz-design.md.
-- Requires: PRAGMA foreign_keys = ON;
--
-- While the template is unreleased, the platform part of this DDL lands in the initial
-- schema migration (edited in place); the reference feature (projects, tasks,
-- project_access) gets its own migration in the app stream — see "Schema evolution".
--
-- Existing tables, for context (see migrations/01_initial_schema.sql):
--   tenants        — unchanged
--   users          — becomes a GLOBAL account: tenant_id is dropped (with its FK and
--                    UNIQUE(tenant_id, id)), which makes the global UNIQUE(email)
--                    correct; email_verified_at DATETIME is added (step 11)
--   refresh_tokens — re-keyed by user_id alone (tenant_id dropped)

-- ---------- RBAC ----------

CREATE TABLE roles (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    -- NULL = seeded system role. "System role" is DEFINED as tenant_id IS NULL — there
    -- is deliberately no separate is_system flag that could contradict it.
    tenant_id  INTEGER REFERENCES tenants(id) ON DELETE CASCADE,
    name       TEXT     NOT NULL,
    kind       TEXT     NOT NULL CHECK (kind IN ('staff', 'client')),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
-- UNIQUE(tenant_id, name) does not constrain NULL tenant_id (NULLs are distinct), so use
-- two partial unique indexes (which cannot be inline table constraints) to cover system
-- vs tenant-custom roles.
CREATE UNIQUE INDEX ux_roles_system_name ON roles(name)            WHERE tenant_id IS NULL;
CREATE UNIQUE INDEX ux_roles_tenant_name ON roles(tenant_id, name) WHERE tenant_id IS NOT NULL;

CREATE TABLE role_permissions (
    role_id    INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission TEXT    NOT NULL, -- validated against the code-side Permission enum on write
    PRIMARY KEY (role_id, permission)
);
-- APP-ENFORCED INVARIANT: client-kind roles never receive a '*:read_all' permission.
-- See "Invariants beyond foreign keys" in authz-design.md.

-- ---------- Membership ----------

CREATE TABLE tenant_memberships (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER  NOT NULL REFERENCES users(id)   ON DELETE CASCADE,
    tenant_id  INTEGER  NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    role_id    INTEGER  NOT NULL REFERENCES roles(id)   ON DELETE RESTRICT,
    status     TEXT     NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (user_id, tenant_id)
);
CREATE INDEX idx_memberships_tenant ON tenant_memberships(tenant_id);
-- role_id is ON DELETE RESTRICT: without this index SQLite scans the table on every role
-- delete; it also serves the "is this role in use" query of role management.
CREATE INDEX idx_memberships_role   ON tenant_memberships(role_id);
-- (user_id lookups are served by the UNIQUE(user_id, tenant_id) index prefix.)

-- INVARIANT 1 (role belongs to the tenant): the assigned role must be a system role
-- (tenant_id IS NULL) or belong to the membership's tenant. A plain FK cannot express
-- the OR, so these triggers enforce it at the DB level; the service validates it too,
-- for friendly errors. See "Invariants beyond foreign keys" in authz-design.md.
CREATE TRIGGER trg_memberships_role_tenant_insert
BEFORE INSERT ON tenant_memberships
FOR EACH ROW
WHEN NOT EXISTS (
    SELECT 1 FROM roles r
    WHERE r.id = NEW.role_id AND (r.tenant_id IS NULL OR r.tenant_id = NEW.tenant_id)
)
BEGIN
    SELECT RAISE(ABORT, 'role_not_in_tenant');
END;

CREATE TRIGGER trg_memberships_role_tenant_update
BEFORE UPDATE OF role_id, tenant_id ON tenant_memberships
FOR EACH ROW
WHEN NOT EXISTS (
    SELECT 1 FROM roles r
    WHERE r.id = NEW.role_id AND (r.tenant_id IS NULL OR r.tenant_id = NEW.tenant_id)
)
BEGIN
    SELECT RAISE(ABORT, 'role_not_in_tenant');
END;

-- ---------- Entities (supertype) + subtypes ----------

CREATE TABLE entities (
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
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by    INTEGER  NOT NULL REFERENCES users(id) ON DELETE NO ACTION,
    updated_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_by    INTEGER  NOT NULL REFERENCES users(id) ON DELETE NO ACTION,
    UNIQUE (tenant_id, id),        -- backs projects.(tenant_id, client_id) FK; also serves tenant_id lookups
    UNIQUE (tenant_id, id, type)   -- backs the typed subtype FKs below
);
CREATE TRIGGER trg_entities_updated_at
AFTER UPDATE ON entities
FOR EACH ROW
BEGIN
    UPDATE entities SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

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
    UNIQUE (tenant_id, name),    -- its index also serves tenant_id lookups by prefix
    UNIQUE (tenant_id, tax_id),
    UNIQUE (tenant_id, registration_number),
    FOREIGN KEY (tenant_id, id, type)
        REFERENCES entities(tenant_id, id, type) ON DELETE CASCADE
);

CREATE TABLE persons (
    id          INTEGER PRIMARY KEY,
    tenant_id   INTEGER NOT NULL,
    type        TEXT    NOT NULL DEFAULT 'person' CHECK (type = 'person'),
    first_name  TEXT,
    last_name   TEXT,
    national_id TEXT,
    details     TEXT CHECK (details IS NULL OR json_valid(details)), -- app extension point
    FOREIGN KEY (tenant_id, id, type)
        REFERENCES entities(tenant_id, id, type) ON DELETE CASCADE
);
CREATE INDEX idx_persons_tenant ON persons(tenant_id);

-- ---------- Client access link (user <-> entity, M2M) ----------

CREATE TABLE entity_users (
    tenant_id  INTEGER  NOT NULL,
    entity_id  INTEGER  NOT NULL,
    user_id    INTEGER  NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (entity_id, user_id),
    FOREIGN KEY (tenant_id, entity_id)
        REFERENCES entities(tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX idx_entity_users_user ON entity_users(user_id);

-- ---------- Invitations ----------

CREATE TABLE invitations (
    id          INTEGER  PRIMARY KEY AUTOINCREMENT,
    tenant_id   INTEGER  NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email       TEXT     NOT NULL COLLATE NOCASE,
    role_id     INTEGER  NOT NULL REFERENCES roles(id) ON DELETE RESTRICT,
    entity_id   INTEGER,           -- set for client invites: which client entity the user joins
    token_hash  TEXT     NOT NULL UNIQUE, -- single-use lookup
    invited_by  INTEGER  NOT NULL REFERENCES users(id) ON DELETE NO ACTION,
    expires_at  DATETIME NOT NULL,
    accepted_at DATETIME,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- NULL entity_id disables this composite FK (staff invites), which is intended.
    FOREIGN KEY (tenant_id, entity_id)
        REFERENCES entities(tenant_id, id) ON DELETE CASCADE
);
-- one open invite per (tenant, email). NOTE: an expired-but-unaccepted invite still
-- occupies this slot, so the create-invite service must REPLACE a pending invite for
-- the same email (delete + insert in one transaction) rather than fail.
CREATE UNIQUE INDEX ux_invitations_pending ON invitations(tenant_id, email)
    WHERE accepted_at IS NULL;
-- no further indexes: invitation volume is tiny; add one when a real query needs it.

-- ---------- Single-use user tokens (email verification, password reset; step 11) ----------

CREATE TABLE user_tokens (
    id          INTEGER  PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER  NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose     TEXT     NOT NULL CHECK (purpose IN ('email_verification', 'password_reset')),
    token_hash  TEXT     NOT NULL UNIQUE,
    expires_at  DATETIME NOT NULL,
    consumed_at DATETIME,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ---------- Reference feature: projects (one client per project) + tasks ----------
-- Business apps built on the template replace these tables and the view (see "Evolving
-- the template and a business app in parallel"). Their DDL lives in a migration of its
-- own, in the app stream, separate from the platform schema.

CREATE TABLE projects (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id   INTEGER  NOT NULL,
    client_id   INTEGER  NOT NULL,
    name        TEXT,
    description TEXT,
    number      TEXT,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by  INTEGER  NOT NULL REFERENCES users(id) ON DELETE NO ACTION,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_by  INTEGER  NOT NULL REFERENCES users(id) ON DELETE NO ACTION,
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    -- the composite FK pins the client to the same tenant (no cross-tenant references).
    -- NO ACTION (checked at end-of-statement) still blocks deleting an entity that has
    -- projects, but lets a tenant-level cascade tear both down without an ordering error
    -- that ON DELETE RESTRICT (checked immediately) would raise.
    FOREIGN KEY (tenant_id, client_id)
        REFERENCES entities(tenant_id, id) ON DELETE NO ACTION
);
-- tenant_id lookups covered by UNIQUE(tenant_id, id) / idx_projects_tenant_client by prefix.
CREATE INDEX idx_projects_tenant_client ON projects(tenant_id, client_id);
CREATE TRIGGER trg_projects_updated_at
AFTER UPDATE ON projects
FOR EACH ROW
BEGIN
    UPDATE projects SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE TABLE tasks (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id  INTEGER  NOT NULL,
    project_id INTEGER  NOT NULL,
    title      TEXT     NOT NULL,
    status     TEXT     NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'done')),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by INTEGER  NOT NULL REFERENCES users(id) ON DELETE NO ACTION,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_by INTEGER  NOT NULL REFERENCES users(id) ON DELETE NO ACTION,
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, project_id)
        REFERENCES projects(tenant_id, id) ON DELETE CASCADE
);
-- lead with project_id so the task-visibility query (WHERE project_id IN (...)) uses the index.
CREATE INDEX idx_tasks_project ON tasks(project_id);
CREATE TRIGGER trg_tasks_updated_at
AFTER UPDATE ON tasks
FOR EACH ROW
BEGIN
    UPDATE tasks SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

-- ---------- Access view (row visibility, one predicate per entity) ----------

-- UNION ALL, not UNION: a deduplicating UNION blocks SQLite's WHERE-clause push-down,
-- so the view would be materialized for ALL users on every query — measured ~1000x
-- slower at modest volume (see "Performance checks" in authz-design.md). With UNION ALL
-- the user_id predicate is pushed into both arms and every query runs index-driven.
-- Dedup is unnecessary anyway: consumers use IN (...) semi-joins, which dedup
-- inherently. A user matching both arms yields two rows for the same project — never
-- read this view without IN / EXISTS / LIMIT 1 / GROUP BY around it.
CREATE VIEW project_access (project_id, tenant_id, user_id, access_level) AS
    -- staff: tenant-wide read via role permission
    SELECT p.id, p.tenant_id, m.user_id, 'staff'
    FROM tenant_memberships m
    JOIN role_permissions   rp ON rp.role_id = m.role_id AND rp.permission = 'project:read_all'
    JOIN projects           p  ON p.tenant_id = m.tenant_id
    WHERE m.status = 'active'
    UNION ALL
    -- client: user linked to the project's client entity
    SELECT p.id, p.tenant_id, eu.user_id, 'client'
    FROM entity_users eu
    JOIN projects     p ON p.tenant_id = eu.tenant_id
                       AND p.client_id = eu.entity_id;
