use axum::Json;
use axum::Router;
use axum::extract::State;
use serde::Serialize;

use crate::api;
use crate::common;
use crate::jwt;

pub fn router<UR>(ctx: common::ArcContext, repo: UR) -> Router<common::ArcContext>
where
    UR: super::TRepository + Clone + 'static,
{
    use axum::routing::get;
    let context = ctx.clone();
    Router::new()
        .route("/users", get(list_users::<UR>))
        .route("/users/me", get(user_info::<UR>))
        .with_state(AppState { context, repo })
        .route_layer(axum::middleware::from_fn_with_state(ctx, crate::auth::middleware))
}

#[derive(Clone)]
struct AppState<UR>
where
    UR: super::TRepository + Clone + 'static,
{
    pub context: common::ArcContext,
    pub repo: UR,
}

#[derive(Serialize)]
pub struct UserResponse {
    pub id: i64,
    pub email: String,
    pub tenant_id: i64,
}

impl From<super::User> for UserResponse {
    fn from(user: super::User) -> Self {
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

impl From<super::UserError> for api::Error {
    fn from(error: super::UserError) -> Self {
        match error {
            super::UserError::NotFound => Self::not_found(),
            super::UserError::AlreadyExists => Self::user_already_exists(),
            super::UserError::InvalidEmail(_) => Self::validation_failed(serde_json::json!({
                "field": "email",
                "message": "invalid email address"
            })),
            super::UserError::Database(repo_error) => {
                tracing::error!("user database error: {repo_error}");
                Self::internal()
            }
        }
    }
}

async fn list_users<UR>(
    State(AppState { context, repo }): State<AppState<UR>>,
    axum::extract::Query(pagination): axum::extract::Query<api::Pagination>,
    claims: jwt::TokenClaims,
) -> Result<Json<ListUsersResponse>, api::Error>
where
    UR: super::TRepository + Clone,
{
    let (limit, offset) = pagination.sanitize();
    let query = super::ListUsersQuery {
        tenant_id: common::TenantId(claims.tenant_id),
        limit,
        offset,
    };

    let result = repo.list_by_tenant(&context.db, query).await?;

    Ok(Json(ListUsersResponse {
        users: result.users.into_iter().map(Into::into).collect(),
        total: result.total,
        limit,
        offset,
    }))
}

async fn user_info<UR>(
    State(AppState { context, repo }): State<AppState<UR>>,
    claims: jwt::TokenClaims,
) -> Result<Json<UserInfoResponse>, api::Error>
where
    UR: super::TRepository + Clone,
{
    let user_id = claims.user_id()?;
    let user = repo.find_by_id(&context.db, common::UserId(user_id)).await?;
    Ok(Json(UserInfoResponse { user: user.into() }))
}
