use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::{self, FromRow, Type};

use crate::db::{DbContext, DbError};

#[derive(Debug, PartialEq, Eq, Type, Serialize, Deserialize)]
#[sqlx(type_name = "TEXT", rename_all = "lowercase")]
pub enum TenantStatus {
    Active,
    Suspended,
    Archived,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct Tenant {
    pub id: i64,
    pub status: TenantStatus,
    pub name: String,
    pub description: Option<String>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NewTenant {
    pub status: TenantStatus,
    pub name: String,
    pub description: Option<String>,
}

pub async fn get_tenant_by_id(db: &DbContext, id: i64) -> Result<Tenant, DbError> {
    let tenant = sqlx::query_as!(
        Tenant,
        r#"
        SELECT
            id as "id!",
            status as "status: TenantStatus",
            name as "name!",
            description,
            created_at as "created_at!",
            updated_at as "updated_at!"
        FROM tenants
        WHERE id = ?
        "#,
        id
    )
    .fetch_one(db)
    .await?;
    Ok(tenant)
}
