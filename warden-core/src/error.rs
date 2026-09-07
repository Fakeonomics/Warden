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
    #[error("invalid header: {0}")] Header(#[from] reqwest::header::InvalidHeaderValue),
    #[error("invalid header name: {0}")] HeaderName(#[from] reqwest::header::InvalidHeaderName),
    #[error("semaphore closed")] SemaphoreClosed(#[from] tokio::sync::AcquireError),
    #[error("crypto: {0}")] Crypto(String),
    #[error("other: {0}")] Other(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use url::Url;

    #[test]
    fn error_display_messages() {
        assert_eq!(WardenError::NoConfigs.to_string(), "no configs available");
        assert_eq!(WardenError::AllFailed.to_string(), "all connection attempts failed");
        assert_eq!(WardenError::ProtocolUnsupported("foo".into()).to_string(), "protocol not supported: foo");
        assert_eq!(WardenError::AuthMissing.to_string(), "auth token missing");
        assert_eq!(WardenError::Api("boom".into()).to_string(), "api error: boom");
        assert_eq!(WardenError::Crypto("fail".into()).to_string(), "crypto: fail");
        assert_eq!(WardenError::Other("oops".into()).to_string(), "other: oops");
    }

    #[test]
    fn error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "missing");
        let warden_err: WardenError = io_err.into();
        match warden_err {
            WardenError::Io(_) => {}
            other => panic!("expected Io variant, got {other:?}"),
        }
    }

    #[test]
    fn error_from_url() {
        let url_err = Url::parse("not a url").unwrap_err();
        let warden_err: WardenError = url_err.into();
        match warden_err {
            WardenError::Url(e) => assert_eq!(e, Url::parse("not a url").unwrap_err()),
            other => panic!("expected Url variant, got {other:?}"),
        }
    }

    #[test]
    fn error_from_json() {
        let json_err = serde_json::from_str::<()>("invalid").unwrap_err();
        let warden_err: WardenError = json_err.into();
        match warden_err {
            WardenError::Json(_) => {}
            other => panic!("expected Json variant, got {other:?}"),
        }
    }
}
