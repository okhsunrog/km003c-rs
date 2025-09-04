pub mod adc;
pub mod capture;
pub mod device;
pub mod error;
pub mod message;
pub mod packet;
pub mod pd;
pub mod python;

// Re-export the KM003C struct for easy access
pub use device::KM003C;
