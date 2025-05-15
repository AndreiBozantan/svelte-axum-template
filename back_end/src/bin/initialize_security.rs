use std::fs;
use std::io::Write;
use uuid::Uuid;
use sqlx::SqlitePool;
use std::sync::Arc;

// Import from parent module
#[path = "../auth_utils.rs"]
mod auth_utils;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load .env file if it exists
    dotenv::dotenv().ok();

    println!("Initializing security settings...");

    // 1. Generate a secure JWT secret
    let jwt_secret = Uuid::new_v4().to_string() + "-" + &Uuid::new_v4().to_string();
    println!("Generated JWT secret");    // 2. Update the config files with the JWT secret
    update_config_file("./config/default.toml", &jwt_secret)?;
    update_config_file("./config/development.toml", &jwt_secret)?;
    
    // 3. Set up admin user with secure password
    // Get database URL from environment
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "sqlite:db.sqlite".to_string());

    println!("Connecting to database: {}", database_url);

    // Connect to the database
    let pool = SqlitePool::connect(&database_url).await?;
    let pool_ref = Arc::new(pool);

    println!("Setting up default admin user...");

    // Hash the default password
    let admin_password = "admin123";
    let password_hash = auth_utils::hash_password(admin_password)?;

    // Update the admin user's password using direct SQL instead of macros
    let query = format!(
        "UPDATE users SET password_hash = '{}' WHERE username = 'admin'",
        password_hash
    );
    
    let rows_affected = sqlx::query(&query)
        .execute(&*pool_ref)
        .await?
        .rows_affected();

    if rows_affected > 0 {
        println!("Admin user password has been set");
        println!("Username: admin");
        println!("Password: {}", admin_password);
    } else {
        // If no admin user exists, create one
        let insert_query = format!(
            "INSERT INTO users (username, password_hash, email, tenant_id, created_at, updated_at) 
             VALUES ('admin', '{}', 'admin@example.com', 1, strftime('%s', 'now'), strftime('%s', 'now'))",
            password_hash
        );
        
        let insert_result = sqlx::query(&insert_query)
            .execute(&*pool_ref)
            .await?;
            
        if insert_result.rows_affected() > 0 {
            println!("Created new admin user");
            println!("Username: admin");
            println!("Password: {}", admin_password);
        } else {
            println!("Failed to create admin user");
        }
    }

    println!("Security initialization complete!");
    Ok(())
}

fn update_config_file(path: &str, jwt_secret: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Check if the file exists
    if !std::path::Path::new(path).exists() {
        println!("Config file {} does not exist, creating it", path);

        // Ensure directory exists
        if let Some(parent) = std::path::Path::new(path).parent() {
            fs::create_dir_all(parent)?;
        }

        // Create config with JWT settings
        let config_content = format!(
            r#"[jwt]
secret = "{}"
access_token_expiry_mins = 15
refresh_token_expiry_mins = 1440
"#,
            jwt_secret
        );

        let mut file = fs::File::create(path)?;
        file.write_all(config_content.as_bytes())?;
        println!("Created new config file: {}", path);
        return Ok(());
    }

    // Read existing config
    let content = fs::read_to_string(path)?;

    // Check if JWT section exists
    if content.contains("[jwt]") {
        // Replace existing secret
        let lines: Vec<&str> = content.lines().collect();
        let mut updated_lines = Vec::new();
        let mut in_jwt_section = false;

        for line in lines {
            if line.starts_with("[jwt]") {
                in_jwt_section = true;
                updated_lines.push(line.to_string());
            } else if in_jwt_section && line.trim().starts_with("secret =") {
                updated_lines.push(format!("secret = \"{}\"", jwt_secret));
            } else if line.starts_with("[") && line != "[jwt]" {
                in_jwt_section = false;
                updated_lines.push(line.to_string());
            } else {
                updated_lines.push(line.to_string());
            }
        }

        let updated_content = updated_lines.join("\n");
        fs::write(path, updated_content)?;
    } else {
        // Append JWT section to file
        let jwt_section = format!(
            r#"
[jwt]
secret = "{}"
access_token_expiry_mins = 15
refresh_token_expiry_mins = 1440
"#,
            jwt_secret
        );

        let mut file = fs::OpenOptions::new().append(true).open(path)?;
        file.write_all(jwt_section.as_bytes())?;
    }

    println!("Updated JWT secret in: {}", path);
    Ok(())
}
