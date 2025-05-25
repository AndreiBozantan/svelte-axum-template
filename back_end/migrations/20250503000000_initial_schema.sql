-- Create tenants table first
CREATE TABLE IF NOT EXISTS tenants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

-- Create users table with tenant_id and SSO support
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT,  -- NULL for SSO-only users
    email TEXT,
    tenant_id INTEGER,
    sso_provider TEXT,   -- 'google', 'microsoft', 'github', etc.
    sso_id TEXT,         -- Provider's user ID
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    UNIQUE(sso_provider, sso_id),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE SET NULL
);

-- Create refresh_tokens table for JWT authentication
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    jti TEXT NOT NULL UNIQUE,  -- JWT ID from the refresh token
    user_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL,  -- Hash of the refresh token for security
    issued_at DATETIME NOT NULL,
    expires_at DATETIME NOT NULL,
    revoked_at DATETIME,        -- When token was revoked (if applicable)
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create access_token_audit table
CREATE TABLE IF NOT EXISTS access_token_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    jti TEXT NOT NULL UNIQUE,  -- JWT ID (safe to store)
    user_id INTEGER NOT NULL,
    issued_at DATETIME NOT NULL,
    expires_at DATETIME NOT NULL,
    user_agent TEXT,
    ip_address TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_users_tenant_id ON users(tenant_id);
CREATE INDEX IF NOT EXISTS idx_users_sso_provider_id ON users(sso_provider, sso_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_jti ON refresh_tokens(jti);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_access_token_audit_jti ON access_token_audit(jti);
CREATE INDEX IF NOT EXISTS idx_access_token_audit_user_id ON access_token_audit(user_id);

-- Create a default tenant for existing users
INSERT OR IGNORE INTO tenants (name, description, created_at, updated_at)
VALUES ('Default', 'Default tenant for system users', strftime('%s', 'now'), strftime('%s', 'now'));