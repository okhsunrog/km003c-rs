pub mod error;
pub mod packet;
pub mod adc;
pub mod message;
pub mod device;

// Re-export the KM003C struct for easy access
pub use device::KM003C;

#[cfg(test)]
mod tests;
