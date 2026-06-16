use crate::platform::identity::oauth;

#[test]
fn accepts_root() {
    assert!(oauth::validate_redirect_path("/").is_ok());
}

#[test]
fn accepts_simple_path() {
    assert!(oauth::validate_redirect_path("/dashboard").is_ok());
}

#[test]
fn accepts_path_with_query_and_fragment() {
    assert!(oauth::validate_redirect_path("/search?q=rust&page=2#results").is_ok());
}

#[test]
fn accepts_path_at_max_length() {
    let path = format!("/{}", "a".repeat(255));
    assert_eq!(path.len(), 256);
    assert!(oauth::validate_redirect_path(&path).is_ok());
}

#[test]
fn accepts_legitimately_percent_encoded_path() {
    // single encoding of a space
    assert!(oauth::validate_redirect_path("/search?q=hello%20world").is_ok());
}

#[test]
fn rejects_path_over_max_length() {
    let path = format!("/{}", "a".repeat(256));
    assert_eq!(path.len(), 257);
    assert!(oauth::validate_redirect_path(&path).is_err());
}

#[test]
fn rejects_empty_string() {
    assert!(oauth::validate_redirect_path("").is_err());
}

#[test]
fn rejects_path_without_leading_slash() {
    assert!(oauth::validate_redirect_path("dashboard").is_err());
}

#[test]
fn rejects_protocol_relative_double_slash() {
    assert!(oauth::validate_redirect_path("//evil.com").is_err());
}

#[test]
fn rejects_triple_slash() {
    assert!(oauth::validate_redirect_path("///evil.com").is_err());
}

#[test]
fn rejects_absolute_http_url() {
    assert!(oauth::validate_redirect_path("http://evil.com").is_err());
}

#[test]
fn rejects_absolute_https_url_disguised_with_leading_slash() {
    // doesn't start with '/', so caught by the leading-slash check anyway
    assert!(oauth::validate_redirect_path("https://evil.com").is_err());
}

#[test]
fn rejects_scheme_after_leading_slash() {
    assert!(oauth::validate_redirect_path("/https://evil.com").is_err());
}

#[test]
fn rejects_javascript_scheme() {
    assert!(oauth::validate_redirect_path("javascript:alert(1)").is_err());
}

#[test]
fn rejects_backslash_backslash() {
    assert!(oauth::validate_redirect_path("/\\evil.com").is_err());
}

#[test]
fn rejects_leading_backslash_variant() {
    assert!(oauth::validate_redirect_path("\\/evil.com").is_err());
}

#[test]
fn rejects_percent_encoded_double_slash() {
    // /%2F%2FEvil.com -> decodes to //Evil.com
    assert!(oauth::validate_redirect_path("/%2F%2FEvil.com").is_err());
}

#[test]
fn rejects_percent_encoded_backslash() {
    // /%5CEvil.com -> decodes to /\Evil.com
    assert!(oauth::validate_redirect_path("/%5CEvil.com").is_err());
}

#[test]
fn rejects_double_percent_encoded_bypass() {
    // /%252F%252FEvil.com -> first decode: /%2F%2FEvil.com (still encoded)
    // -> second decode: //evil.com
    assert!(oauth::validate_redirect_path("/%252F%252FEvil.com").is_err());
}

#[test]
fn rejects_percent_encoded_scheme() {
    // /%68%74%74%70%3A%2F%2FEvil.com -> http://Evil.com
    assert!(oauth::validate_redirect_path("/%68%74%74%70%3A%2F%2FEvil.com").is_err());
}

#[test]
fn rejects_invalid_utf8_percent_encoding() {
    assert!(oauth::validate_redirect_path("/%ff%fe").is_err());
}

#[test]
fn rejects_newline() {
    assert!(oauth::validate_redirect_path("/foo\nbar").is_err());
}

#[test]
fn rejects_carriage_return() {
    assert!(oauth::validate_redirect_path("/foo\rbar").is_err());
}

#[test]
fn rejects_tab() {
    assert!(oauth::validate_redirect_path("/foo\tbar").is_err());
}

#[test]
fn rejects_null_byte() {
    assert!(oauth::validate_redirect_path("/foo\0bar").is_err());
}

#[test]
fn rejects_percent_encoded_newline() {
    // CRLF injection via encoding, e.g. for response splitting
    assert!(oauth::validate_redirect_path("/foo%0d%0aBar").is_err());
}

#[test]
fn rejects_percent_encoded_null_byte() {
    assert!(oauth::validate_redirect_path("/foo%00bar").is_err());
}
