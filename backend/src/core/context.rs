use crate::core::config::{Config, JwtConfig};
use jsonwebtoken as jwt;

pub type ArcContext = std::sync::Arc<Context>;

pub type DbContext = sqlx::SqlitePool;

pub type DbError = sqlx::Error;


#[derive(Clone)]
pub struct JwtContext {
    pub encoding_key: jwt::EncodingKey,
    pub decoding_key: jwt::DecodingKey,
    pub validation: jwt::Validation,
    pub access_token_expiry: i64,
    pub refresh_token_expiry: i64,
}

#[derive(Clone)]
pub struct Context {
    pub db: DbContext,
    pub jwt: JwtContext,
    pub config: Config,
    pub http_client: reqwest::Client,
}

impl Context {
    pub fn new(db: DbContext, config: Config) -> Result<ArcContext, reqwest::Error> {
        let jwt = JwtContext::new(&config.jwt);
        let http_client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {db, jwt, config, http_client}.into())
    }
}

impl JwtContext {
    pub fn new(config: &JwtConfig) -> Self {
        let encoding_key = jwt::EncodingKey::from_secret(config.secret.as_ref());
        let decoding_key = jwt::DecodingKey::from_secret(config.secret.as_ref());
        let mut validation = jwt::Validation::new(jwt::Algorithm::HS256);
        validation.leeway = 0;

        Self {
            encoding_key,
            decoding_key,
            validation,
            access_token_expiry: config.access_token_expiry,
            refresh_token_expiry: config.refresh_token_expiry,
        }
    }
}
