use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::routing::get;
use serde::Serialize;

use crate::auth;
use crate::common::ApiError;
use crate::common::ArcContext;
use crate::common::Pagination;
use crate::jwt;

use super::domain::{ListUsersQuery, TenantId, UserError, UserId, UserRepo};
use super::domain::Service as UserService;

pub fn router<UR>(ctx: ArcContext, user_service: UserService<UR>) -> Router<ArcContext>
where
    UR: UserRepo + Clone + 'static,
{
    Router::new()
        .route("/users", get(list_users::<UR>))
        .route("/users/me", get(user_info::<UR>))
        .with_state((ctx.clone(), user_service))
        .route_layer(axum::middleware::from_fn_with_state(ctx, auth::middleware))
}

#[derive(Serialize)]
pub struct UserResponse {
    pub id: i64,
    pub email: String,
    pub tenant_id: i64,
}

impl From<&crate::identity::users::domain::User> for UserResponse {
    fn from(user: &crate::identity::users::domain::User) -> Self {
        Self {
            id: user.id.0,
            email: user.email.as_str().to_string(),
            tenant_id: user.tenant_id.0,
        }
    }
}

#[derive(Serialize)]
pub struct ListUsersResponse {
    users: Vec<UserResponse>,
    total: i64,
    limit: i64,
    offset: i64,
}

#[derive(Serialize)]
pub struct UserInfoResponse {
    pub user: UserResponse,
}

impl From<UserError> for ApiError {
    fn from(error: UserError) -> Self {
        match error {
            UserError::NotFound => Self::not_found(),
            UserError::AlreadyExists => Self::user_already_exists(),
            UserError::InvalidEmail => Self::validation_failed(serde_json::json!({
                "field": "email",
                "message": "invalid email address"
            })),
            UserError::Database(repo_error) => {
                tracing::error!("user database error: {repo_error}");
                Self::internal()
            }
        }
    }
}

pub async fn list_users<UR>(
    State((context, service)): State<(ArcContext, UserService<UR>)>,
    axum::extract::Query(pagination): axum::extract::Query<Pagination>,
    claims: jwt::TokenClaims,
) -> Result<Json<ListUsersResponse>, ApiError>
where
    UR: UserRepo + Clone,
{
    let (limit, offset) = pagination.sanitize();
    let result = service
        .list_users(
            &context.db,
            ListUsersQuery {
                tenant_id: TenantId(claims.tenant_id),
                limit,
                offset,
            },
        )
        .await?;

    Ok(Json(ListUsersResponse {
        users: result.users.iter().map(Into::into).collect(),
        total: result.total,
        limit,
        offset,
    }))
}

pub async fn user_info<UR>(
    State((context, service)): State<(ArcContext, UserService<UR>)>,
    claims: jwt::TokenClaims,
) -> Result<Json<UserInfoResponse>, ApiError>
where
    UR: UserRepo + Clone,
{
    let user_id = claims.user_id().map_err(|_| ApiError::not_authenticated())?;
    let user = service.get_user(&context.db, UserId(user_id)).await?;
    Ok(Json(UserInfoResponse { user: (&user).into() }))
}
