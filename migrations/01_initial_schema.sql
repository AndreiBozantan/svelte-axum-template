CREATE TABLE IF NOT EXISTS tenants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status TEXT NOT NULL CHECK(status IN ('active', 'suspended', 'archived')),
    name TEXT NOT NULL,
    description TEXT
);
-- auto update trigger for updated_at 
CREATE TRIGGER IF NOT EXISTS trg_tenants_updated_at
AFTER UPDATE ON tenants
FOR EACH ROW
BEGIN
    UPDATE tenants SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;
-- create the default tenant for self-signup/SSO users
INSERT OR IGNORE INTO tenants (id, created_at, updated_at, status, name, description)
VALUES (0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'active', 'Default', 'Default tenant for public users');
-- create the system tenant for platform administration
INSERT OR IGNORE INTO tenants (id, created_at, updated_at, status, name, description)
VALUES (1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'active', 'System', 'System tenant for internal platform operations');

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status TEXT NOT NULL CHECK(status IN ('onboarding', 'active', 'suspended', 'archived')),
    email TEXT NOT NULL COLLATE NOCASE,
    first_name TEXT,
    middle_name TEXT,
    last_name TEXT,
    password_hash TEXT,  -- NULL for SSO-only users
    sso_provider TEXT,   -- 'google', 'microsoft', 'github', etc.
    sso_id TEXT,         -- Provider's user ID
    failed_login_count INTEGER NOT NULL DEFAULT 0,
    last_failed_login DATETIME,
    UNIQUE(email),
    UNIQUE(tenant_id, id),
    UNIQUE(sso_provider, sso_id),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_users_tenant_id ON users(tenant_id);
-- auto update trigger for updated_at 
CREATE TRIGGER IF NOT EXISTS trg_users_updated_at
AFTER UPDATE ON users
FOR EACH ROW
BEGIN
    UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;
-- create a default system user (id=0) for internal operations, associated with the system tenant (tenant_id=1)
INSERT OR IGNORE INTO users (id, tenant_id, created_at, updated_at, status, email, first_name, last_name)
VALUES (0, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'active', 'admin@system.local', 'super', 'admin');

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    jti TEXT NOT NULL UNIQUE,  -- JWT ID from the refresh token
    token_hash TEXT NOT NULL,  -- Hash of the refresh token for security
    issued_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    revoked_at DATETIME,        -- When token was revoked (if applicable)
    FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_tenant_user ON refresh_tokens(tenant_id, user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);


