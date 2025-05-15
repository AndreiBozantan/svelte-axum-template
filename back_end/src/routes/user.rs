use std::sync::Arc;
use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;

use crate::auth_utils::hash_password;
use crate::db::schema::{User, NewUser};
use crate::store::Store;

#[derive(Debug, Error)]
pub enum UserError {
    #[error("User not found")]
    UserNotFound,

    #[error("User already exists")]
    UserAlreadyExists,

    #[error("Password hashing failed")]
    PasswordHashingFailed,

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

impl IntoResponse for UserError {
    fn into_response(self) -> axum::response::Response {
        tracing::error!("{}", &self);

        let (status, error_message) = match self {
            Self::UserNotFound => (StatusCode::NOT_FOUND, self.to_string()),
            Self::UserAlreadyExists => (StatusCode::CONFLICT, self.to_string()),
            Self::PasswordHashingFailed => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            Self::DatabaseError(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            Self::InvalidInput(_) => (StatusCode::BAD_REQUEST, self.to_string()),
        };

        let body = Json(json!({
            "result": "error",
            "message": error_message
        }));

        (status, body).into_response()
    }
}

#[derive(Deserialize)]
pub struct CreateUserRequest {
    username: String,
    password: String,
    email: Option<String>,
    tenant_id: Option<i64>,
}

#[derive(Deserialize)]
pub struct UpdateUserRequest {
    password: Option<String>,
    email: Option<String>,
    tenant_id: Option<i64>,
}

#[derive(Serialize)]
pub struct UserResponse {
    id: i64,
    username: String,
    email: Option<String>,
    tenant_id: Option<i64>,
    created_at: i64,
    updated_at: i64,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            username: user.username,
            email: user.email,
            tenant_id: user.tenant_id,
            created_at: user.created_at,
            updated_at: user.updated_at,
        }
    }
}

/// Create a new user
#[allow(clippy::unused_async)]
pub async fn create_user(
    State(store): State<Arc<Store>>,
    Json(user_req): Json<CreateUserRequest>,
) -> Result<impl IntoResponse, UserError> {
    // Validate inputs
    if user_req.username.trim().is_empty() {
        return Err(UserError::InvalidInput("Username cannot be empty".to_string()));
    }
    
    if user_req.password.trim().is_empty() || user_req.password.len() < 8 {
        return Err(UserError::InvalidInput("Password must be at least 8 characters".to_string()));
    }

    // Check if user already exists
    match store.get_user_by_username(&user_req.username).await {
        Ok(_) => return Err(UserError::UserAlreadyExists),
        Err(crate::store::StoreError::UserNotFound) => {}, // This is expected
        Err(e) => return Err(UserError::DatabaseError(e.to_string())),
    };

    // Hash the password
    let password_hash = hash_password(&user_req.password)
        .map_err(|_| UserError::PasswordHashingFailed)?;

    // Create user object
    let new_user = NewUser {
        username: user_req.username,
        password_hash,
        email: user_req.email,
        tenant_id: user_req.tenant_id,
    };

    // Save user to database
    let user = store.create_user(new_user).await
        .map_err(|e| UserError::DatabaseError(e.to_string()))?;

    // Return user info (excluding password)
    Ok((StatusCode::CREATED, Json(UserResponse::from(user))))
}

/// Get user by ID
#[allow(clippy::unused_async)]
pub async fn get_user(
    State(store): State<Arc<Store>>,
    axum::extract::Path(user_id): axum::extract::Path<i64>,
) -> Result<impl IntoResponse, UserError> {
    let user = store.get_user_by_id(user_id).await
        .map_err(|e| match e {
            crate::store::StoreError::UserNotFound => UserError::UserNotFound,
            _ => UserError::DatabaseError(e.to_string()),
        })?;

    Ok(Json(UserResponse::from(user)))
}

/// Update user
#[allow(clippy::unused_async)]
pub async fn update_user(
    State(store): State<Arc<Store>>,
    axum::extract::Path(user_id): axum::extract::Path<i64>,
    Json(update_req): Json<UpdateUserRequest>,
) -> Result<impl IntoResponse, UserError> {
    // First get the existing user
    let mut user = store.get_user_by_id(user_id).await
        .map_err(|e| match e {
            crate::store::StoreError::UserNotFound => UserError::UserNotFound,
            _ => UserError::DatabaseError(e.to_string()),
        })?;

    // Update password if provided
    if let Some(password) = update_req.password {
        if password.trim().is_empty() || password.len() < 8 {
            return Err(UserError::InvalidInput("Password must be at least 8 characters".to_string()));
        }
        
        user.password_hash = hash_password(&password)
            .map_err(|_| UserError::PasswordHashingFailed)?;
    }

    // Update email if provided
    if let Some(email) = update_req.email {
        user.email = Some(email);
    }

    // Update tenant if provided
    if let Some(tenant_id) = update_req.tenant_id {
        user.tenant_id = Some(tenant_id);
    }

    // Save updated user
    let updated_user = store.update_user(user_id, user).await
        .map_err(|e| UserError::DatabaseError(e.to_string()))?;

    Ok(Json(UserResponse::from(updated_user)))
}
