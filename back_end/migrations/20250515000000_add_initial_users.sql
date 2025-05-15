-- Create a default admin user with password "password123" (will be hashed during runtime)
INSERT INTO users (username, password_hash, email, tenant_id, created_at, updated_at)
VALUES 
    ('admin', 'temp_password_to_be_reset', 'admin@example.com', 1, strftime('%s', 'now'), strftime('%s', 'now'))
ON CONFLICT(username) DO NOTHING;
