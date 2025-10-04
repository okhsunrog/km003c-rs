use std::array::TryFromSliceError;
use std::io;
use thiserror::Error;

/// The primary error type for the `km003c-rs` library.
#[derive(Error, Debug)]
pub enum KMError {
    #[error("USB device not found. Is the POWER-Z KM003C connected?")]
    DeviceNotFound,

    #[error("USB error: {0}")]
    Usb(#[from] nusb::Error),

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Timeout during USB operation: {0}")]
    Timeout(#[from] tokio::time::error::Elapsed),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Invalid packet: {0}")]
    InvalidPacket(String),

    #[error("Invalid length")]
    InvalidLength,

    #[error("Insufficient data: expected at least {expected} bytes, got {actual}")]
    InsufficientData { expected: usize, actual: usize },

    #[error("Index out of bounds")]
    IndexOutOfBounds,
    
    #[error("Parse error at offset {offset}: {message}")]
    ParseError { offset: usize, message: String },
    
    #[error("Attribute mismatch: expected {expected:?}, got {actual:?}")]
    AttributeMismatch {
        expected: Vec<u16>,
        actual: Vec<u16>,
    },
    
    #[error("Empty PutData response (obj_count_words=0) - device has no data")]
    EmptyResponse,
    
    #[error("Transaction ID mismatch: request={request}, response={response}")]
    TransactionIdMismatch { request: u8, response: u8 },
}

impl From<TryFromSliceError> for KMError {
    fn from(_: TryFromSliceError) -> Self {
        KMError::InvalidPacket("Failed to convert slice to array".to_string())
    }
}
