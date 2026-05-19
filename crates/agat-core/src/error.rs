use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Vault error: {0}")]
    Vault(String),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Sample not found: {0}")]
    SampleNotFound(String),

    #[error("Invalid sample: {0}")]
    InvalidSample(String),

    #[error("Database error: {0}")]
    Database(String),

    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("Hex decode error: {0}")]
    Hex(#[from] hex::FromHexError),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;
