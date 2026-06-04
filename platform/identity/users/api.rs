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

use super::service::{ListUsersQuery, TenantId, UserError, UserId, UserRepo, UserService};

#[derive(Clone)]
pub struct UsersState<UR: UserRepo> {
    pub context: ArcContext,
    pub service: UserService<UR>,
}

pub fn router<UR>(ctx: ArcContext, user_service: UserService<UR>) -> Router<ArcContext>
where
    UR: UserRepo + Clone + 'static,
{
    let state = UsersState {
        context: ctx.clone(),
        service: user_service,
    };
    Router::new()
        .route("/users", get(list_users::<UR>))
        .route("/users/me", get(user_info::<UR>))
        .route_layer(axum::middleware::from_fn_with_state(ctx, auth::middleware))
        .with_state(state)
}

#[derive(Serialize)]
pub struct UserResponse {
    pub id: i64,
    pub email: String,
    pub tenant_id: i64,
}

impl From<&crate::identity::users::service::User> for UserResponse {
    fn from(user: &crate::identity::users::service::User) -> Self {
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
    State(state): State<UsersState<UR>>,
    axum::extract::Query(pagination): axum::extract::Query<Pagination>,
    claims: jwt::TokenClaims,
) -> Result<Json<ListUsersResponse>, ApiError>
where
    UR: UserRepo + Clone,
{
    let (limit, offset) = pagination.sanitize();
    let result = state
        .service
        .list_users(
            &state.context.db,
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
    State(state): State<UsersState<UR>>,
    claims: jwt::TokenClaims,
) -> Result<Json<UserInfoResponse>, ApiError>
where
    UR: UserRepo + Clone,
{
    let user_id = claims.user_id().map_err(|_| ApiError::not_authenticated())?;
    let user = state.service.get_user(&state.context.db, UserId(user_id)).await?;
    Ok(Json(UserInfoResponse { user: (&user).into() }))
}
