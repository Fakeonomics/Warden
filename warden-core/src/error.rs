use thiserror::Error;

#[derive(Error, Debug)]
pub enum WardenError {
    #[error("No configs available")]
    NoConfigs,
    #[error("All connection attempts failed")]
    AllFailed,
    #[error("Protocol not supported: {0}")]
    ProtocolUnsupported(String),
    #[error("Auth token missing")]
    AuthMissing,
    #[error("API error: {0}")]
    Api(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("URL parse: {0}")]
    Url(#[from] url::ParseError),
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Crypto: {0}")]
    Crypto(String),
    #[error("Other: {0}")]
    Other(String),
}
