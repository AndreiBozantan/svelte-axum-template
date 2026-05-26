use serde::Deserialize;

const fn default_limit() -> i64 {
    50
}

#[derive(Deserialize)]
pub struct Pagination {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}
