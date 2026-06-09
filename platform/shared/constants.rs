pub mod auth {
    /// Maximum allowed failed login attempts within the defined window before account is temporarily locked.
    pub const FAILED_LOGIN_MAX_ATTEMPTS: i64 = 5;

    /// Defines the time window in minutes for counting failed login attempts.
    ///
    /// If a user exceeds the maximum allowed failed attempts within this window, their account will be temporarily locked.
    /// This is a security measure to prevent brute-force attacks.
    pub const FAILED_LOGIN_WINDOW_MINUTES: i64 = 5;
}

pub mod env {
    pub const PRODUCTION: &str = "production";
    pub const DEVELOPMENT: &str = "development";
    pub const TEST: &str = "test";
}

pub mod db {
    pub const DEFAULT_TENANT_ID_FOR_NEW_SSO_USERS: i64 = 0;
}
