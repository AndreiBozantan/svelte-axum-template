CREATE TABLE IF NOT EXISTS tenants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('active', 'suspended', 'archived')),
    name TEXT NOT NULL,
    description TEXT
);
-- create a default tenant, for new users who sign up without specifying a tenant (e.g., via SSO) or 
-- for system users that don't belong to any specific tenant
INSERT OR IGNORE INTO tenants (id, created_at, updated_at, status, name, description)
VALUES (0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'active', 'Default', 'Default tenant for system users');

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('onboarding', 'active', 'suspended', 'archived')),
    email TEXT NOT NULL,
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
CREATE UNIQUE INDEX users_email_case_insensitive ON users(LOWER(email));
-- create a default system user for internal operations, associated with the default tenant
INSERT OR IGNORE INTO users (id, tenant_id, created_at, updated_at, status, email, first_name, last_name)
VALUES (0, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'active', 'sa@app.com', 'super', 'admin');

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    jti TEXT NOT NULL UNIQUE,  -- JWT ID from the refresh token
    token_hash TEXT NOT NULL,  -- Hash of the refresh token for security
    issued_at DATETIME NOT NULL,
    expires_at DATETIME NOT NULL,
    revoked_at DATETIME,        -- When token was revoked (if applicable)
    FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_cleanup
ON refresh_tokens(expires_at) WHERE revoked_at IS NOT NULL;


