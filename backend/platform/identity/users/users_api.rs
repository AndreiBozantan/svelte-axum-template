use axum;
use axum::extract::State;
use serde::Serialize;
use utoipax;

use crate::platform::api;
use crate::platform::common;
use crate::platform::identity::users;
use crate::platform::jwt;

pub fn router(service: users::Service) -> utoipax::router::OpenApiRouter<common::ArcContext> {
    use utoipax::routes;
    utoipax::router::OpenApiRouter::new()
        .routes(routes!(list_users))
        .routes(routes!(user_info))
        .with_state(service)
}

#[derive(Serialize, utoipa::ToSchema)]
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

#[derive(Serialize, utoipa::ToSchema)]
pub struct ListUsersResponse {
    pub users: Vec<UserResponse>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct UserInfoResponse {
    pub user: UserResponse,
}

impl From<users::Error> for api::Error {
    fn from(error: users::Error) -> Self {
        match error {
            users::Error::NotFound => Self::not_found(),
            users::Error::AlreadyExists => Self::user_already_exists(),
            users::Error::DatabaseOperationFailed(_) => Self::internal(),
        }
    }
}

#[utoipa::path(
    get,
    path = "/users",
    params(
        ("limit" = Option<i64>, Query, description = "Pagination limit"),
        ("offset" = Option<i64>, Query, description = "Pagination offset")
    ),
    responses(
        (status = 200, description = "List of users successful", body = ListUsersResponse),
        (status = 401, description = "Unauthorized", body = api::Error)
    ),
    security(
        ("cookieAuth" = [])
    )
)]
async fn list_users(
    State(service): State<users::Service>,
    pagination: api::Pagination,
    claims: jwt::TokenClaims,
) -> Result<axum::Json<ListUsersResponse>, api::Error> {
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

#[utoipa::path(
    get,
    path = "/users/me",
    responses(
        (status = 200, description = "Get current user info successful", body = UserInfoResponse),
        (status = 401, description = "Unauthorized", body = api::Error)
    ),
    security(
        ("cookieAuth" = [])
    )
)]
async fn user_info(
    State(service): State<users::Service>,
    claims: jwt::TokenClaims,
) -> Result<axum::Json<UserInfoResponse>, api::Error> {
    let tenant_id = claims.tenant_id();
    let user_id = claims.user_id()?;
    let user = service
        .users
        .find_by_id(&service.context.db, tenant_id, user_id)
        .await?;
    Ok(axum::Json(UserInfoResponse { user: user.into() }))
}
