use jsonwebtoken as jwt;
use crate::core::config::Config;
use crate::core::config::JwtConfig;
use crate::core::dbpool::DbPoolType;

pub type ArcContext = std::sync::Arc<Context>;

#[derive(Clone)]
pub struct Context {
    pub db: DbPoolType,
    pub jwt: JwtContext,
    pub config: Config,
    pub http_client: reqwest::Client,
}

#[derive(Clone)]
pub struct JwtContext {
    pub encoding_key: jwt::EncodingKey,
    pub decoding_key: jwt::DecodingKey,
    pub validation: jwt::Validation,
    pub access_token_expiry: i64,
    pub refresh_token_expiry: i64,
}

impl Context {
    pub fn new(db: DbPoolType, config: Config) -> Self {
        let jwt = JwtContext::new(&config.jwt);
        let http_client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("Failed to create HTTP client");
        Self {db, jwt, config, http_client}
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
