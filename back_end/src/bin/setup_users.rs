use sqlx::SqlitePool;
use std::sync::Arc;

// Import from parent module
#[path = "../auth_utils.rs"]
mod auth_utils;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load .env file if it exists
    dotenv::dotenv().ok();

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

    // Update the admin user's password
    // Use query_as instead of query to avoid SQLx macro issues
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
        println!("No admin user found to update");
    }

    Ok(())
}
