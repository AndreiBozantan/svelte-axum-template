/// Clean up and canonicalize email addresses for consistent storage and comparison.
#[must_use]
pub fn normalize_email(email: &str) -> String {
    email.trim().to_ascii_lowercase()
}

