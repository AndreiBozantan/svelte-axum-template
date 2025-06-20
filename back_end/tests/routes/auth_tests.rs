use svelte_axum_template::routes::auth::*;

#[test]
fn test_login_struct_deserialization() {
    let json_str = r#"{"username": "testuser", "password": "testpass"}"#;
    let login: Login = serde_json::from_str(json_str).unwrap();

    assert_eq!(login.username, "testuser");
    assert_eq!(login.password, "testpass");
}