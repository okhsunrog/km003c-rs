//! Common test utilities and shared imports

// Allow unused imports and dead code since this is a shared module
// used across multiple test files - not all items are used in every test file
#[allow(unused_imports)]
pub use bytes::Bytes;
#[allow(unused_imports)]
pub use hex;
#[allow(unused_imports)]
pub use km003c_lib::adc::SampleRate;
#[allow(unused_imports)]
pub use km003c_lib::error::KMError;
#[allow(unused_imports)]
pub use km003c_lib::message::Packet;
#[allow(unused_imports)]
pub use km003c_lib::packet::{Attribute, CtrlHeader, DataHeader, ExtendedHeader, PacketType, RawPacket};
#[allow(unused_imports)]
pub use num_enum::FromPrimitive;

/// Decode hex string to bytes for testing
#[allow(dead_code)]
pub fn hex_to_bytes(hex_data: &str) -> Bytes {
    Bytes::from(hex::decode(hex_data).expect("Failed to decode hex"))
}

/// Real ADC response data for testing
#[allow(dead_code)]
pub const REAL_ADC_RESPONSE: &[u8] = &[
    0x41, 0x00, 0x80, 0x02, 0x01, 0x00, 0x00, 0x0b, 0x45, 0x1c, 0x4d, 0x00, 0xae, 0x9e, 0xfe, 0xff, 0xdb, 0x1c, 0x4d,
    0x00, 0x23, 0x9f, 0xfe, 0xff, 0xe1, 0x1c, 0x4d, 0x00, 0x81, 0x9f, 0xfe, 0xff, 0xc9, 0x0c, 0x8a, 0x10, 0x0e, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x78, 0x7e, 0x00, 0x80, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Extended ADC data with extended header for testing
#[allow(dead_code)]
pub const EXTENDED_ADC_DATA: &str =
    "410c82020100000be08d4d001e000000218e4d00eaffffff278e4d00480000001c0c9502737e000001007b7e0080a40c00000000";
