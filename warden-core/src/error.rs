use thiserror::Error;

#[derive(Error, Debug)]
pub enum WardenError {
    #[error("no configs available")] NoConfigs,
    #[error("all connection attempts failed")] AllFailed,
    #[error("protocol not supported: {0}")] ProtocolUnsupported(String),
    #[error("auth token missing")] AuthMissing,
    #[error("api error: {0}")] Api(String),
    #[error("io: {0}")] Io(#[from] std::io::Error),
    #[error("http: {0}")] Http(#[from] reqwest::Error),
    #[error("url: {0}")] Url(#[from] url::ParseError),
    #[error("json: {0}")] Json(#[from] serde_json::Error),
    #[error("crypto: {0}")] Crypto(String),
    #[error("other: {0}")] Other(String),
}
