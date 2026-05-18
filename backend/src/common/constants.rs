pub mod err_msg {
    pub const INTERNAL: &str = "An internal server error occurred";
    pub const SSO_OPERATION_FAILED: &str = "SSO authentication failed";
    pub const USER_ALREADY_EXISTS: &str = "User with the given email already exists";
    pub const INVALID_CREDENTIALS: &str = "Invalid credentials";
    pub const TOKEN_EXPIRED: &str = "Authentication token has expired";
    pub const INVALID_TOKEN: &str = "Invalid authentication token";
}

pub mod auth {
    /// Maximum allowed failed login attempts within the defined window before account is temporarily locked.
    pub const FAILED_LOGIN_MAX_ATTEMPTS: i64 = 5;

    /// Defines the time window in minutes for counting failed login attempts.
    ///
    /// If a user exceeds the maximum allowed failed attempts within this window, their account will be temporarily locked.
    /// This is a security measure to prevent brute-force attacks.
    pub const FAILED_LOGIN_WINDOW_MINUTES: i64 = 5;
}
