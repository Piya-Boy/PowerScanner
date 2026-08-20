use thiserror::Error;

#[derive(Error, Debug)]
pub enum PsError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("signature error: {0}")]
    Signature(String),
    #[error("yara error: {0}")]
    Yara(String),
    #[error("config error: {0}")]
    Config(String),
    #[error("tamper detected: {0}")]
    Tamper(String),
}

pub type PsResult<T> = Result<T, PsError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_formats_variant() {
        let e = PsError::Tamper("bad hmac".into());
        assert_eq!(e.to_string(), "tamper detected: bad hmac");
    }

    #[test]
    fn io_error_converts() {
        let io = std::io::Error::new(std::io::ErrorKind::NotFound, "x");
        let e: PsError = io.into();
        assert!(matches!(e, PsError::Io(_)));
    }
}
