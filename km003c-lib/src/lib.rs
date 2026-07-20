pub mod adc;
pub mod adcqueue;
pub mod auth;
pub mod constants;
pub mod device;
pub mod error;
pub mod message;
pub mod packet;
pub mod pd;
#[cfg(feature = "usbpd")]
pub mod pd_decode;

#[cfg(feature = "python")]
pub mod python;

#[cfg(feature = "python")]
pub use python::*;

// Re-export commonly used types
pub use adcqueue::{AdcQueueData, AdcQueueSample, GraphSampleRate, sequence_elapsed};
pub use auth::{DeviceInfo, HardwareId, StreamingAuthResult};
pub use device::{ConnectionMode, DeviceConfig, DeviceState, KM003C, TransferType};
pub use message::{Packet, PayloadData};
pub use packet::{Attribute, AttributeSet, LogicalPacket, RawPacket};
pub use pd::{PdEvent, PdEventData, PdEventStream, PdStatus};
#[cfg(feature = "usbpd")]
pub use pd_decode::{
    DecodedPdEvent, DecodedPdMessage, PdChunkState, PdChunkStatus, PdDecodeError, PdDecodeFailure, PdSessionDecoder,
};
pub use uom;
#[cfg(feature = "usbpd")]
pub use usbpd;
