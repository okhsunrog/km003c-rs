// src/error.rs

use nusb::transfer::TransferError;
use thiserror::Error;

/// The primary error type for the `km003c-rs` library.
#[derive(Error, Debug)]
pub enum Error {
    #[error("USB device not found. Is the POWER-Z KM003C connected?")]
    DeviceNotFound,

    #[error("USB error: {0}")]
    Usb(#[from] nusb::Error),

    // NEW VARIANT to handle the specific error from `into_result()`
    #[error("USB transfer error: {0}")]
    Transfer(#[from] TransferError),

    #[error("Timeout during USB operation: {0}")]
    Timeout(#[from] tokio::time::error::Elapsed),

    #[error("Protocol error: {0}")]
    Protocol(String),
}
