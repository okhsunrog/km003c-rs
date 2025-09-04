pub mod adc;
pub mod device;
pub mod error;
pub mod message;
pub mod packet;

#[cfg(feature = "python")]
pub mod python;

// Re-export the KM003C struct for easy access
pub use device::KM003C;
