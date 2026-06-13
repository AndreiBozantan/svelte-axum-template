use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::response::Response;
use serde::Deserialize;
use serde::Serialize;
use tracing::error;
use tracing::info;

use crate::platform::db;
use crate::platform::jwt;

#[derive(Debug, Clone, thiserror::Error, Serialize)]
#[error("{message}")]
pub struct Error {
    #[serde(skip)]
    status: StatusCode,
    code: &'static str,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<ValidationErrorsMap>,
}

pub type ValidationErrorsMap = std::collections::HashMap<String, Vec<String>>;

impl Error {
    #[must_use]
    pub fn new(
        status: StatusCode,
        code: &'static str,
        message: impl Into<String>,
        details: Option<ValidationErrorsMap>,
    ) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            details,
        }
    }

    #[must_use]
    pub fn internal() -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "An unexpected error occurred.",
            None,
        )
    }

    #[must_use]
    pub fn invalid_credentials() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
            "Email or password is incorrect",
            None,
        )
    }

    #[must_use]
    pub fn sso_failed() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "sso_failed",
            "Single sign-on authentication failed.",
            None,
        )
    }

    #[must_use]
    pub fn expired_token() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "expired_token",
            "Authentication token has expired.",
            None,
        )
    }

    #[must_use]
    pub fn invalid_token() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "Authentication token is invalid.",
            None,
        )
    }

    #[must_use]
    pub fn not_found() -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "not_found",
            "The requested resource is not found.",
            None,
        )
    }

    #[must_use]
    pub fn validation_failed(
        field: &str,
        message: &str,
    ) -> Self {
        let mut map = std::collections::HashMap::new();
        map.insert(field.to_string(), vec![message.to_string()]);
        Self::validation_errors_with_status(StatusCode::BAD_REQUEST, map)
    }

    #[must_use]
    pub fn validation_failed_with_status(
        status: StatusCode,
        field: &str,
        message: &str,
    ) -> Self {
        let mut map = std::collections::HashMap::new();
        map.insert(field.to_string(), vec![message.to_string()]);
        Self::validation_errors_with_status(status, map)
    }

    #[must_use]
    pub fn validation_errors_with_status(
        status: StatusCode,
        errors: ValidationErrorsMap,
    ) -> Self {
        Self::new(status, "validation_failed", "Request validation failed.", Some(errors))
    }

    #[must_use]
    pub fn user_already_exists() -> Self {
        Self::conflict("user_already_exists", "A user with the given email already exists.")
    }

    #[must_use]
    pub fn db_key_violation(code: &'static str) -> Self {
        Self::conflict(code, "A data validation error occurred.")
    }

    #[must_use]
    pub fn conflict(
        code: &'static str,
        message: impl Into<String>,
    ) -> Self {
        Self::new(StatusCode::CONFLICT, code, message, None)
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let status = self.status;
        if status.is_server_error() {
            error!(code = %self.code, error = %self.message, "internal_server_error");
        } else {
            info!(status = status.as_u16(), code = %self.code, "client_error");
        }
        (status, axum::Json(self)).into_response()
    }
}

impl From<jwt::Error> for Error {
    fn from(error: jwt::Error) -> Self {
        match error {
            jwt::Error::ExpiredToken => Self::expired_token(),
            jwt::Error::InvalidToken => Self::invalid_token(),
            _ => Self::internal(),
        }
    }
}

impl From<db::Error> for Error {
    fn from(error: db::Error) -> Self {
        match error {
            db::Error::RowNotFound => Self::not_found(),
            db::Error::UniqueConstraintViolation(_) => Self::db_key_violation("unique_violation"),
            db::Error::ForeignKeyViolation(_) => Self::db_key_violation("foreign_key_violation"),
            db::Error::CheckConstraintViolation(_) => Self::db_key_violation("check_violation"),
            db::Error::DatabaseOperationFailed(_) => Self::internal(),
            db::Error::RowConversionFailed(_) => Self::internal(),
        }
    }
}

impl From<axum::http::Error> for Error {
    fn from(_error: axum::http::Error) -> Self {
        Self::internal()
    }
}

impl From<axum::http::header::InvalidHeaderValue> for Error {
    fn from(_error: axum::http::header::InvalidHeaderValue) -> Self {
        Self::internal()
    }
}

#[derive(Deserialize)]
struct RawPagination {
    #[serde(default = "default_pagination_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

#[derive(Debug, Clone, Copy)]
pub struct Pagination {
    pub limit: i64,
    pub offset: i64,
}

const fn default_pagination_limit() -> i64 {
    20
}

impl<S> axum::extract::FromRequestParts<S> for Pagination
where
    S: Send + Sync,
{
    type Rejection = Error;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let Query(raw) = Query::<RawPagination>::from_request_parts(parts, state).await?;
        let limit = raw.limit.clamp(1, 200);
        let offset = raw.offset.max(0);
        Ok(Self { limit, offset })
    }
}

/// A custom JSON extractor that wraps axum's standard `Json` extractor to intercept
/// deserialization/parsing errors and return them as a structured `api::Error`.
pub struct Json<T>(pub T);

impl<T> Json<T> {
    pub fn data(self) -> T {
        self.0
    }
}

impl<T> From<T> for Json<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<T, S> axum::extract::FromRequest<S> for Json<T>
where
    T: serde::de::DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = Error;

    async fn from_request(
        req: axum::extract::Request,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        match axum::Json::<T>::from_request(req, state).await {
            Ok(axum::Json(value)) => Ok(Self(value)),
            Err(rejection) => {
                let status = rejection.status();
                let message = rejection.body_text();
                Err(Error::validation_failed_with_status(status, "body", &message))
            },
        }
    }
}

impl<T> IntoResponse for Json<T>
where
    T: Serialize,
{
    fn into_response(self) -> Response {
        axum::Json(self.0).into_response()
    }
}

/// A custom Query extractor that wraps axum's standard `Query` extractor to intercept
/// parsing errors and return them as a structured `api::Error`.
pub struct Query<T>(pub T);

impl<T> Query<T> {
    pub fn data(self) -> T {
        self.0
    }
}

impl<T, S> axum::extract::FromRequestParts<S> for Query<T>
where
    T: serde::de::DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = Error;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        match axum::extract::Query::<T>::from_request_parts(parts, state).await {
            Ok(axum::extract::Query(value)) => Ok(Self(value)),
            Err(rejection) => {
                let status = rejection.status();
                let message = rejection.body_text();
                Err(Error::validation_failed_with_status(status, "query", &message))
            },
        }
    }
}

/// A custom JSON extractor that wraps our custom `Json` extractor and additionally
/// performs validation using the `validator` crate.
pub struct ValidatedJson<T>(pub T);

impl<T> ValidatedJson<T> {
    pub fn data(self) -> T {
        self.0
    }
}

impl<T, S> axum::extract::FromRequest<S> for ValidatedJson<T>
where
    T: serde::de::DeserializeOwned + validator::Validate,
    S: Send + Sync,
{
    type Rejection = Error;

    async fn from_request(
        req: axum::extract::Request,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let Json(value) = Json::<T>::from_request(req, state).await?;
        value.validate().map_err(|errors| {
            let mut errs = std::collections::HashMap::new();
            for (field, field_errors) in errors.field_errors() {
                let messages = field_errors
                    .iter()
                    .map(|err| {
                        err.message
                            .as_ref()
                            .map_or_else(|| "Invalid value".to_string(), std::string::ToString::to_string)
                    })
                    .collect::<Vec<_>>();
                errs.insert(field.to_string(), messages);
            }
            Error::validation_errors_with_status(StatusCode::BAD_REQUEST, errs)
        })?;
        Ok(Self(value))
    }
}

impl<S> axum::extract::FromRequestParts<S> for jwt::TokenClaims
where
    S: Send + Sync,
{
    type Rejection = Error;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        parts.extensions.get().cloned().ok_or_else(Error::invalid_token)
    }
}
