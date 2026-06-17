pub mod auth {
    /// Maximum allowed failed login attempts within the defined window before account is temporarily locked.
    pub const FAILED_LOGIN_MAX_ATTEMPTS: i64 = 5;

    /// Grace period in seconds for refresh token reuse (to handle concurrent requests/retries).
    pub const REFRESH_TOKEN_GRACE_PERIOD_SECONDS: i64 = 10;
}

pub mod env {
    pub const PRODUCTION: &str = "production";
    pub const DEVELOPMENT: &str = "development";
    pub const TEST: &str = "test";
}

pub mod db {
    pub const DEFAULT_TENANT_ID_FOR_NEW_SSO_USERS: i64 = 0;
}
