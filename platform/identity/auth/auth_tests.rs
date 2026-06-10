use crate::api;
use crate::common;
use crate::identity::auth;
use crate::identity::users;
use crate::identity::tokens;

#[tokio::test]
async fn oauth_login_new_user_success() -> anyhow::Result<()> {
    use crate::identity::users::TRepository;
    let ctx = common::Context::create_test_context().await?;
    let auth_service = auth::Service::new(users::db::Repository, tokens::db::Repository);

    let email = common::Email::parse("oauth_new@example.com").ok_or_else(api::Error::invalid_credentials)?;
    let command = auth::OAuthLoginCommand {
        email: email.clone(),
        sso_provider: "google".to_string(),
        sso_id: "google-sso-id-123".to_string(),
    };

    // first login should succeed and create the user
    let res = auth_service.login_oauth(&ctx, command).await?;
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
    let res_subsequent = auth_service.login_oauth(&ctx, command_subsequent).await?;
    assert_eq!(res_subsequent.user.id, res.user.id);
    assert_eq!(res_subsequent.user.email.as_str(), "oauth_new@example.com");

    Ok(())
}

#[tokio::test]
async fn oauth_user_linking_existing_password_user() -> anyhow::Result<()> {
    use crate::identity::users::TRepository;

    let ctx = common::Context::create_test_context().await?;
    let auth_service = auth::Service::new(users::db::Repository, tokens::db::Repository);

    let email = common::Email::parse("link_me@example.com").ok_or_else(api::Error::invalid_credentials)?;
    // register user with password first
    let user = auth_service
        .register(&ctx, email.clone(), "super_secure_pass_123", Some("First".to_string()), Some("Last".to_string()))
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
    let res = auth_service.login_oauth(&ctx, command).await?;
    assert_eq!(res.user.id, user.id);

    // Query DB to verify SSO info was linked
    let sso_info_after = users::db::Repository.find_sso_info_by_id(&ctx.db, user.id).await?;
    assert_eq!(sso_info_after.sso_provider, Some("google".to_string()));
    assert_eq!(sso_info_after.sso_id, Some("google-linked-id".to_string()));

    // verify they can still log in with their password
    let password_login = auth_service.login(&ctx, auth::LoginCommand {
        email: email.clone(),
        password: "super_secure_pass_123".to_string(),
    }).await?;
    assert_eq!(password_login.user.id, user.id);

    Ok(())
}

#[tokio::test]
async fn oauth_user_password_login_failure() -> anyhow::Result<()> {
    let ctx = common::Context::create_test_context().await?;
    let auth_service = auth::Service::new(users::db::Repository, tokens::db::Repository);

    let email = common::Email::parse("oauth_only@example.com").ok_or_else(api::Error::invalid_credentials)?;
    let command = auth::OAuthLoginCommand {
        email: email.clone(),
        sso_provider: "google".to_string(),
        sso_id: "google-sso-id-999".to_string(),
    };

    let res = auth_service.login_oauth(&ctx, command).await?;
    assert_eq!(res.user.email.as_str(), "oauth_only@example.com");

    // try logging in with password - should fail since there is no password_hash
    let password_login_res = auth_service.login(&ctx, auth::LoginCommand {
        email,
        password: "some_random_password".to_string(),
    }).await;

    assert!(password_login_res.is_err());
    assert!(matches!(password_login_res, Err(crate::auth::Error::InvalidCredentials)));

    Ok(())
}
