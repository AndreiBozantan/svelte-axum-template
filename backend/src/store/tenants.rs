use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

use crate::app::{DbError, DbPoolType};

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct Tenant {
    pub id: i64,
    pub name: String,
    pub description: Option<String>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NewTenant {
    pub name: String,
    pub description: Option<String>,
}

pub struct Tenants {
    db: DbPoolType
}

impl Tenants {
    pub fn new(db: DbPoolType) -> Self {
        Self { db }
    }

    pub async fn get_by_id(&self, id: i64) -> Result<Tenant, DbError> {
        let tenant = sqlx::query_as!(
            Tenant,
            r#"
            SELECT
                id as "id!",
                name as "name!",
                description as "description!",
                created_at as "created_at!",
                updated_at as "updated_at!"
            FROM tenants
            WHERE id = ?
            "#,
            id
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => DbError::TenantNotFound,
            _ => DbError::OperationFailed(e),
        })?;
        return Ok(tenant)
    }

}
