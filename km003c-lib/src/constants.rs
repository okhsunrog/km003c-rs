// Protocol constants for KM003C

/// Size of main packet header (4 bytes)
pub const MAIN_HEADER_SIZE: usize = 4;

/// Size of extended header in logical packets (4 bytes)
pub const EXTENDED_HEADER_SIZE: usize = 4;

/// Size of PD preamble (12 bytes)
pub const PD_PREAMBLE_SIZE: usize = 12;

/// Size of PD status block (12 bytes)
pub const PD_STATUS_SIZE: usize = 12;

/// Size of PD event header (6 bytes)
pub const PD_EVENT_HEADER_SIZE: usize = 6;

/// Size of ADC data payload (44 bytes)
pub const ADC_DATA_SIZE: usize = 44;

/// Minimum size for a valid packet (header only)
pub const MIN_PACKET_SIZE: usize = MAIN_HEADER_SIZE;

/// PD event type: connection status
pub const PD_EVENT_TYPE_CONNECTION: u8 = 0x45;

/// PD connection event code: connect
pub const PD_CONNECTION_CONNECT: u8 = 0x11;

/// PD connection event code: disconnect
pub const PD_CONNECTION_DISCONNECT: u8 = 0x12;

/// Mask for extracting wire length from PD event size_flag
pub const PD_EVENT_SIZE_MASK: u8 = 0x3F;

/// Offset to subtract from masked size to get wire length
pub const PD_EVENT_SIZE_OFFSET: u8 = 5;
