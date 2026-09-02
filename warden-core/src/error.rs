use thiserror::Error;

#[derive(Error, Debug)]
pub enum WardenError {
    #[error("no configs available")]
    NoConfigsAvailable,
    #[error("all connections failed")]
    AllConnectionsFailed,
    #[error("protocol not supported: {0}")]
    ProtocolNotSupported(String),
    #[error("config parse error: {0}")]
    ConfigParseError(String),
    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("tunnel error: {0}")]
    TunnelError(String),
    #[error("invalid header: {0}")]
    InvalidHeader(#[from] reqwest::header::InvalidHeaderValue),
    #[error("acquire error: {0}")]
    AcquireError(String),
    #[error("no configs")]
    NoConfigs,
    #[error("all failed")]
    AllFailed,
    #[error("auth token missing")]
    AuthTokenMissing,
    #[error("api error: {0}")]
    Api(String),
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("url: {0}")]
    Url(#[from] url::ParseError),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("crypto: {0}")]
    Crypto(String),
    #[error("update error: {0}")]
    Update(String),
    #[error("download error: {0}")]
    Download(String),
    #[error("other: {0}")]
    Other(String),
}
