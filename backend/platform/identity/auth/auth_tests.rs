use crate::platform::api;
use crate::platform::common;
use crate::platform::identity::auth;
use crate::platform::identity::tokens;
use crate::platform::identity::users;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[tokio::test]
async fn oauth_login_new_user_success() -> TestResult {
    let ctx = common::Context::create_test_context().await?;
    let auth_service = auth::Service::new(users::db::Repository, tokens::db::Repository, ctx.clone());

    let email = common::Email::parse("oauth_new@example.com").ok_or_else(api::Error::invalid_credentials)?;
    let command = auth::OAuthLoginCommand {
        email: email.clone(),
        sso_provider: "google".to_string(),
        sso_id: "google-sso-id-123".to_string(),
    };

    // first login should succeed and create the user
    let res = auth_service.login_oauth(command).await?;
    assert_eq!(res.user.email.as_str(), "oauth_new@example.com");
    assert!(!res.access_token.value.is_empty());
    assert!(!res.refresh_token.value.is_empty());

    // query DB to verify SSO fields
    let sso_info = users::db::Repository.find_sso_info_by_id(&ctx.db, res.user.id).await?;
    assert_eq!(sso_info.sso_provider, Some("google".to_string()));
    assert_eq!(sso_info.sso_id, Some("google-sso-id-123".to_string()));

    // subsequent login should return the same user
    let command_subsequent = auth::OAuthLoginCommand {
        email: email.clone(),
        sso_provider: "google".to_string(),
        sso_id: "google-sso-id-123".to_string(),
    };
    let res_subsequent = auth_service.login_oauth(command_subsequent).await?;
    assert_eq!(res_subsequent.user.id, res.user.id);
    assert_eq!(res_subsequent.user.email.as_str(), "oauth_new@example.com");

    Ok(())
}

#[tokio::test]
async fn oauth_user_linking_existing_password_user() -> TestResult {
    let ctx = common::Context::create_test_context().await?;
    let auth_service = auth::Service::new(users::db::Repository, tokens::db::Repository, ctx.clone());

    let email = common::Email::parse("link_me@example.com").ok_or_else(api::Error::invalid_credentials)?;
    // register user with password first
    let user = auth_service
        .register(
            email.clone(),
            "super_secure_pass_123".to_string(),
            Some("First".to_string()),
            Some("Last".to_string()),
        )
        .await?;

    // Query DB to verify no SSO info initially
    let sso_info_init = users::db::Repository.find_sso_info_by_id(&ctx.db, user.id).await?;
    assert!(sso_info_init.sso_provider.is_none());
    assert!(sso_info_init.sso_id.is_none());

    // login via OAuth with same email
    let command = auth::OAuthLoginCommand {
        email: email.clone(),
        sso_provider: "google".to_string(),
        sso_id: "google-linked-id".to_string(),
    };
    let res = auth_service.login_oauth(command).await?;
    assert_eq!(res.user.id, user.id);

    // Query DB to verify SSO info was linked
    let sso_info_after = users::db::Repository.find_sso_info_by_id(&ctx.db, user.id).await?;
    assert_eq!(sso_info_after.sso_provider, Some("google".to_string()));
    assert_eq!(sso_info_after.sso_id, Some("google-linked-id".to_string()));

    // verify they can still log in with their password
    let cmd = auth::LoginCommand {
        email: email.clone(),
        password: "super_secure_pass_123".to_string(),
    };
    let password_login = auth_service.login(cmd).await?;
    assert_eq!(password_login.user.id, user.id);

    Ok(())
}

#[tokio::test]
async fn oauth_user_password_login_failure() -> TestResult {
    let ctx = common::Context::create_test_context().await?;
    let auth_service = auth::Service::new(users::db::Repository, tokens::db::Repository, ctx.clone());

    let email = common::Email::parse("oauth_only@example.com").ok_or_else(api::Error::invalid_credentials)?;
    let command = auth::OAuthLoginCommand {
        email: email.clone(),
        sso_provider: "google".to_string(),
        sso_id: "google-sso-id-999".to_string(),
    };

    let res = auth_service.login_oauth(command).await?;
    assert_eq!(res.user.email.as_str(), "oauth_only@example.com");

    // try logging in with password - should fail since there is no password_hash
    let cmd = auth::LoginCommand {
        email,
        password: "some_random_password".to_string(),
    };
    let password_login_res = auth_service.login(cmd).await;

    assert!(password_login_res.is_err());
    assert!(matches!(password_login_res, Err(auth::Error::InvalidCredentials)));

    Ok(())
}

#[tokio::test]
async fn suspended_user_login_and_refresh_failure() -> TestResult {
    let ctx = common::Context::create_test_context().await?;
    let auth_service = auth::Service::new(users::db::Repository, tokens::db::Repository, ctx.clone());

    let email = common::Email::parse("suspended@example.com").ok_or_else(api::Error::invalid_credentials)?;
    let user = auth_service
        .register(
            email.clone(),
            "super_secure_pass_123".to_string(),
            Some("Suspended".to_string()),
            Some("User".to_string()),
        )
        .await?;

    // Initial login should succeed when user is active
    let login_cmd = auth::LoginCommand {
        email: email.clone(),
        password: "super_secure_pass_123".to_string(),
    };
    let auth_res = auth_service.login(login_cmd.clone()).await?;
    assert_eq!(auth_res.user.id, user.id);

    // Now suspend the user in the database
    sqlx::query("UPDATE users SET status = 'suspended' WHERE id = ?")
        .bind(user.id.0)
        .execute(&ctx.db)
        .await?;

    // Subsequent login should fail
    let login_err = auth_service.login(login_cmd).await;
    assert!(login_err.is_err());
    assert!(matches!(login_err, Err(auth::Error::InvalidCredentials)));

    // Refresh should fail
    let refresh_err = auth_service.refresh(&auth_res.refresh_token.value).await;
    assert!(refresh_err.is_err());
    assert!(matches!(refresh_err, Err(auth::Error::InvalidToken)));

    Ok(())
}
