use axum;
use axum::extract::State;
use serde::Serialize;

use crate::platform::api;
use crate::platform::auth;
use crate::platform::common;
use crate::platform::identity::users;
use crate::platform::jwt;

pub fn router<UR>(service: users::Service<UR>) -> axum::Router<common::ArcContext>
where
    UR: users::TRepository + Clone + 'static,
{
    use axum::routing::get;
    let ctx = service.context.clone();
    axum::Router::new()
        .route("/users", get(list_users::<UR>))
        .route("/users/me", get(user_info::<UR>))
        .with_state(service)
        .route_layer(axum::middleware::from_fn_with_state(ctx, auth::middleware))
}

#[derive(Serialize)]
pub struct UserResponse {
    pub id: i64,
    pub email: String,
    pub tenant_id: i64,
}

impl From<users::User> for UserResponse {
    fn from(user: users::User) -> Self {
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

impl From<users::Error> for api::Error {
    fn from(error: users::Error) -> Self {
        tracing::error!("user database error: {error}");
        match error {
            users::Error::NotFound => Self::not_found(),
            users::Error::AlreadyExists => Self::user_already_exists(),
            users::Error::DatabaseOperationFailed(_) => Self::internal(),
        }
    }
}

async fn list_users<UR>(
    State(service): State<users::Service<UR>>,
    pagination: api::Pagination,
    claims: jwt::TokenClaims,
) -> Result<axum::Json<ListUsersResponse>, api::Error>
where
    UR: users::TRepository + Clone + 'static,
{
    let query = users::ListUsersQuery {
        tenant_id: common::TenantId(claims.tenant_id),
        limit: pagination.limit,
        offset: pagination.offset,
    };
    let result = service.users.list_by_tenant(&service.context.db, query).await?;
    Ok(axum::Json(ListUsersResponse {
        users: result.users.into_iter().map(Into::into).collect(),
        total: result.total,
        limit: pagination.limit,
        offset: pagination.offset,
    }))
}

async fn user_info<UR>(
    State(service): State<users::Service<UR>>,
    claims: jwt::TokenClaims,
) -> Result<axum::Json<UserInfoResponse>, api::Error>
where
    UR: users::TRepository + Clone + 'static,
{
    let user_id = claims.user_id()?;
    let user = service
        .users
        .find_by_id(&service.context.db, common::UserId(user_id))
        .await?;
    Ok(axum::Json(UserInfoResponse { user: user.into() }))
}
