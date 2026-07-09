use crate::platform::config::AppSettings;

#[test]
fn test_default_config_is_valid() {
    let settings = AppSettings::default();
    assert!(settings.validate().is_ok());
}

#[test]
fn test_invalid_environment_fails() {
    let res = crate::platform::config::get_app_env_impl(|key| {
        if key == "APP__SERVER__ENV" {
            Some("invalid_env".to_string())
        } else {
            None
        }
    });
    let Err(err) = res else {
        panic!("expected get_app_env_impl to fail with invalid environment");
    };
    let err_msg = err.to_string();
    assert!(err_msg.contains("invalid server environment"));
}

#[test]
fn test_empty_database_url_fails() {
    let mut settings = AppSettings::default();
    settings.database.url = String::new();
    let Err(err) = settings.validate() else {
        panic!("expected ValidationError");
    };
    let err_msg = err.to_string();
    assert!(err_msg.contains("database URL cannot be empty"));
}

#[test]
fn test_invalid_database_url_fails() {
    let mut settings = AppSettings::default();
    settings.database.url = "postgres://localhost/db".to_string();
    let Err(err) = settings.validate() else {
        panic!("expected ValidationError");
    };
    let err_msg = err.to_string();
    assert!(err_msg.contains("invalid database URL"));
}

#[test]
fn test_partial_oauth_fails_missing_secret() {
    let mut settings = AppSettings::default();
    settings.oauth.google_client_id = "some-id".to_string();
    settings.oauth.google_redirect_uri = "https://localhost/oauth".to_string();
    let Err(err) = settings.validate() else {
        panic!("expected ValidationError");
    };
    let err_msg = err.to_string();
    assert!(err_msg.contains("Google Client Secret is required"));
}

#[test]
fn test_partial_oauth_fails_missing_uri() {
    let mut settings = AppSettings::default();
    settings.oauth.google_client_id = "some-id".to_string();
    settings.oauth.google_client_secret = "some-secret".to_string();
    let Err(err) = settings.validate() else {
        panic!("expected ValidationError");
    };
    let err_msg = err.to_string();
    assert!(err_msg.contains("Google Redirect URI is required"));
}

#[test]
fn test_oauth_non_https_redirect_on_non_localhost_fails() {
    let mut settings = AppSettings::default();
    settings.oauth.google_client_id = "some-id".to_string();
    settings.oauth.google_client_secret = "some-secret".to_string();
    settings.oauth.google_redirect_uri = "http://example.com/oauth".to_string();
    let Err(err) = settings.validate() else {
        panic!("expected ValidationError");
    };
    let err_msg = err.to_string();
    assert!(err_msg.contains("must use HTTPS in non-localhost environments"));
}

#[test]
fn test_oauth_http_redirect_on_localhost_succeeds() {
    let mut settings = AppSettings::default();
    settings.oauth.google_client_id = "some-id".to_string();
    settings.oauth.google_client_secret = "some-secret".to_string();
    settings.oauth.google_redirect_uri = "http://localhost/oauth".to_string();
    assert!(settings.validate().is_ok());
}

#[test]
fn test_valid_oauth_succeeds() {
    let mut settings = AppSettings::default();
    settings.oauth.google_client_id = "some-id".to_string();
    settings.oauth.google_client_secret = "some-secret".to_string();
    settings.oauth.google_redirect_uri = "https://example.com/oauth".to_string();
    assert!(settings.validate().is_ok());
}

#[test]
fn test_env_from_process_env_only() -> Result<(), Box<dyn std::error::Error>> {
    let env = crate::platform::config::get_app_env_impl(|key| {
        if key == "APP__SERVER__ENV" {
            Some("test".to_string())
        } else {
            None
        }
    })?;
    assert_eq!(env, "test");
    Ok(())
}
