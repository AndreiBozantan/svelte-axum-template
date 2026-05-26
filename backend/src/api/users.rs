use axum::Json;
use axum::body::Body;
use axum::extract::Query;
use axum::extract::Request;
use axum::extract::State;
use serde::Serialize;

use crate::auth;
use crate::common;
use crate::common::ApiError;
use crate::db;

#[derive(Serialize)]
pub struct User {
    pub id: i64,
    pub email: String,
    pub tenant_id: i64,
}

impl From<&db::User> for User {
    fn from(u: &db::User) -> Self {
        Self {
            id: u.id,
            email: u.email.clone(),
            tenant_id: u.tenant_id,
        }
    }
}

#[derive(Serialize)]
pub struct ListUsersResponse {
    users: Vec<User>,
    total: i64,
    limit: i64,
    offset: i64,
}

#[derive(Serialize)]
pub struct UserInfoResponse {
    pub user: User,
}

pub async fn list_users(
    State(context): State<common::ArcContext>,
    Query(pagination): Query<common::types::Pagination>,
    req: Request<Body>,
) -> Result<Json<ListUsersResponse>, common::ApiError> {
    let claims =
        auth::decode_token_from_req(&context, &req, auth::TokenType::Access).map_err(|e| common::ApiError::from(&e))?;

    let limit = pagination.limit.clamp(1, 200);
    let offset = pagination.offset.max(0);

    let (users, total) = tokio::try_join!(
        db::get_users_by_tenant_id(&context.db, claims.tenant_id, limit, offset),
        db::count_users_by_tenant_id(&context.db, claims.tenant_id),
    )
    .map_err(|_| common::ApiError::internal())?;

    Ok(Json(ListUsersResponse {
        users: users.iter().map(Into::into).collect(),
        total,
        limit,
        offset,
    }))
}

/// User info handler - returns user information based on the access token
pub async fn user_info(
    State(context): State<common::ArcContext>,
    req: Request<Body>,
) -> Result<Json<UserInfoResponse>, common::ApiError> {
    let claims =
        auth::decode_token_from_req(&context, &req, auth::TokenType::Access).map_err(|err| ApiError::from(&err))?;
    let user_id = claims.user_id().map_err(|_| common::ApiError::not_authenticated())?;
    let user = db::get_user_by_id(&context.db, user_id)
        .await
        .map_err(|_| common::ApiError::not_authenticated())?;
    Ok(Json(UserInfoResponse { user: (&user).into() }))
}
