pub mod adc;
pub mod adcqueue;
pub mod auth;
pub mod constants;
pub mod device;
pub mod error;
pub mod measurement;
pub mod message;
pub mod offline;
pub mod offline_view;
pub mod packet;
pub mod pd;
pub mod pd_connection;
#[cfg(feature = "usbpd")]
pub mod pd_contract;
#[cfg(feature = "usbpd")]
pub mod pd_decode;
#[cfg(feature = "usbpd")]
pub mod pd_log;
pub mod pd_trace;
#[cfg(feature = "preferences")]
pub mod preferences;
pub mod recording;
pub mod session;
pub mod settings;

#[cfg(feature = "python")]
pub mod python;

#[cfg(feature = "python")]
pub use python::*;

// Re-export commonly used types
pub use adcqueue::{
    AdcQueueData, AdcQueueRawData, AdcQueueSample, AdcQueueSampleRaw, GraphSampleRate, sequence_elapsed,
};
pub use auth::{AuthCredential, DeviceInfo, HardwareId, StreamingAuthResult};
pub use device::{ConnectionMode, DeviceConfig, DeviceSelector, DeviceState, KM003C, TransferType};
pub use measurement::{MeasurementAccumulator, MeasurementSample, Metric};
pub use message::{Packet, PayloadData};
pub use offline::{LogMetadata, LogMetadataResponse, OfflineLog, OfflineLogSample, OfflineLogSampleRaw};
pub use offline_view::{OfflineRecordingView, OfflineViewSample};
pub use packet::{Attribute, AttributeSet, LogicalPacket, PacketPeek, RawPacket};
pub use pd::{PdEvent, PdEventData, PdEventStream, PdStatus};
pub use pd_connection::PdConnectionTracker;
#[cfg(feature = "usbpd")]
pub use pd_contract::{PdContract, PdContractStage};
#[cfg(feature = "usbpd")]
pub use pd_decode::{
    DecodedPdEvent, DecodedPdMessage, PdChunkState, PdChunkStatus, PdDecodeError, PdDecodeFailure, PdSessionDecoder,
};
#[cfg(feature = "usbpd")]
pub use pd_log::{PdLogCategory, PdLogEntry, PdLogger};
pub use pd_trace::{
    PdProtocolTraceEventKind, PdTrace, PdTraceCategory, PdTraceEntry, PdTraceProtocolEvent, PdTraceStateEvent,
    PdTypeCState,
};
#[cfg(feature = "polars")]
pub use polars;
#[cfg(feature = "preferences")]
pub use preferences::{Preferences, PreferencesError};
#[cfg(feature = "polars")]
pub use recording::{
    OfflineExport, OfflineExportEvent, Recorder, RecordingError, RecordingEvent, RecoveryOutcome,
    measurements_to_dataframe, read_recording, recording_schema, recover_interrupted, write_offline_recording,
};
pub use recording::{RECORDING_SCHEMA_VERSION, RecordingFormat, RecordingMetadata, RecordingSummary};
pub use session::{Session, SessionClosed, SessionCommand, SessionEvent};
pub use settings::Settings;
pub use uom;
#[cfg(feature = "usbpd")]
pub use usbpd;
