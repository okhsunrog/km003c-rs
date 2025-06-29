pub mod adc;
pub mod analysis;
pub mod device;
pub mod error;
pub mod message;
pub mod packet;
pub mod pd;

// Re-export the KM003C struct for easy access
pub use device::KM003C;
