//! USB PD state-machine trace data exposed through attribute `0x0020`.

use num_enum::{FromPrimitive, IntoPrimitive};
use uom::si::f64::Time;
use uom::si::time::second;

use crate::error::KMError;

const TRACE_RECORD_SIZE: usize = 5;
const MAX_QUEUE_BYTES: usize = 200;

/// Type-C state codes embedded in the KM003C V1.9.9 firmware.
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromPrimitive, IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum PdTypeCState {
    Disabled = 0x00,
    DelayUnattached = 0x01,
    AttachedResistance = 0x02,
    TryResistance = 0x03,
    AttachedDebSource = 0x04,
    UnattachedDebSource = 0x05,
    AttachWaitDebSource = 0x06,
    TryDebSource = 0x07,
    AttachedSource = 0x08,
    UnattachedSource = 0x09,
    AttachWaitSource = 0x0a,
    TryWaitSource = 0x0b,
    TrySource = 0x0c,
    DebugAccessorySource = 0x0d,
    AttachedCable = 0x0e,
    IllegalCable = 0x0f,
    AttachWaitCable = 0x10,
    AttachWaitMonitorDefective = 0x11,
    AttachedLightningPlug = 0x12,
    AttachWaitLightningPlug = 0x13,
    AttachedDebSink = 0x14,
    AttachWaitDebSink = 0x15,
    TryWaitDebSink = 0x16,
    AttachedSink = 0x17,
    AttachWaitSink = 0x18,
    TryWaitSink = 0x19,
    TrySink = 0x1a,
    DebugAccessorySink = 0x1b,
    AttachedMonitor = 0x1c,
    AttachWaitMonitor = 0x1d,
    CableCross = 0x1e,
    CablePlugShortCircuit = 0x1f,
    ErrorRecovery = 0x20,
    PoweredAccessory = 0x21,
    UnsupportedAccessory = 0x22,
    AudioAccessory = 0x23,
    AttachWaitAccessory = 0x24,
    #[num_enum(catch_all)]
    Unknown(u8),
}

/// Firmware protocol-engine trace codes confirmed in KM003C V1.9.9.
///
/// Most values in this queue are internal protocol-engine states whose names
/// are not present in the firmware. The two non-state markers below are
/// emitted directly by the receive path and have independently recoverable
/// semantics. All other values are preserved losslessly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromPrimitive, IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum PdProtocolTraceEventKind {
    /// The protocol engine was reset while the Type-C state detached.
    Disabled = 0x00,
    /// A received PD message or extended-message chunk was processed.
    ReceivedMessage = 0x82,
    /// The receive path queued a request for the next extended-message chunk.
    ExtendedChunkRequest = 0x83,
    #[num_enum(catch_all)]
    Unknown(u8),
}

/// One Type-C state transition with a one-second-resolution uptime timestamp.
#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "python", pyo3::pyclass(skip_from_py_object))]
pub struct PdTraceStateEvent {
    pub state: PdTypeCState,
    /// Device uptime when the transition was recorded.
    pub timestamp: Time,
}

/// One raw protocol/message event with a one-second-resolution timestamp.
#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "python", pyo3::pyclass(skip_from_py_object))]
pub struct PdTraceProtocolEvent {
    /// Typed firmware marker, or a losslessly preserved protocol-engine state.
    pub kind: PdProtocolTraceEventKind,
    /// Device uptime when the event was recorded.
    pub timestamp: Time,
}

/// Two trace queues returned by the KM003C USB PD state machine.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "python", pyo3::pyclass(skip_from_py_object))]
pub struct PdTrace {
    /// High-level USB PD state transitions.
    pub state_events: Vec<PdTraceStateEvent>,
    /// Protocol and message-processing events.
    pub protocol_events: Vec<PdTraceProtocolEvent>,
}

impl PdTrace {
    /// Parse the two length-prefixed event queues.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KMError> {
        let (state_records, offset) = parse_queue(bytes, 0, "state")?;
        let (protocol_records, offset) = parse_queue(bytes, offset, "protocol")?;

        if offset != bytes.len() {
            return Err(KMError::InvalidPacket(format!(
                "PD trace has {} trailing bytes",
                bytes.len() - offset
            )));
        }

        Ok(Self {
            state_events: state_records
                .into_iter()
                .map(|record| PdTraceStateEvent {
                    state: PdTypeCState::from_primitive(record.code),
                    timestamp: record.timestamp,
                })
                .collect(),
            protocol_events: protocol_records
                .into_iter()
                .map(|record| PdTraceProtocolEvent {
                    kind: PdProtocolTraceEventKind::from_primitive(record.code),
                    timestamp: record.timestamp,
                })
                .collect(),
        })
    }

    /// Serialize the trace using the firmware queue layout.
    pub fn to_bytes(&self) -> Result<Vec<u8>, KMError> {
        let mut bytes = Vec::new();
        append_queue(
            &mut bytes,
            self.state_events.iter().map(|event| TraceRecord {
                code: event.state.into(),
                timestamp: event.timestamp,
            }),
            "state",
        )?;
        append_queue(
            &mut bytes,
            self.protocol_events.iter().map(|event| TraceRecord {
                code: event.kind.into(),
                timestamp: event.timestamp,
            }),
            "protocol",
        )?;
        Ok(bytes)
    }
}

pub(crate) fn payload_size(bytes: &[u8]) -> Result<usize, KMError> {
    let state_size = queue_size(bytes, 0, "state")?;
    let protocol_offset = 1 + state_size;
    let protocol_size = queue_size(bytes, protocol_offset, "protocol")?;
    Ok(protocol_offset + 1 + protocol_size)
}

fn queue_size(bytes: &[u8], offset: usize, name: &str) -> Result<usize, KMError> {
    let size = usize::from(*bytes.get(offset).ok_or_else(|| {
        KMError::InvalidPacket(format!(
            "PD trace is missing the {name} queue length at offset {offset}"
        ))
    })?);

    if size > MAX_QUEUE_BYTES {
        return Err(KMError::InvalidPacket(format!(
            "PD trace {name} queue is too large: {size} bytes, maximum is {MAX_QUEUE_BYTES}"
        )));
    }
    if !size.is_multiple_of(TRACE_RECORD_SIZE) {
        return Err(KMError::InvalidPacket(format!(
            "PD trace {name} queue length must be a multiple of {TRACE_RECORD_SIZE}, got {size}"
        )));
    }
    if bytes.len().saturating_sub(offset + 1) < size {
        return Err(KMError::InvalidPacket(format!(
            "PD trace {name} queue is truncated: expected {size} bytes, got {}",
            bytes.len().saturating_sub(offset + 1)
        )));
    }

    Ok(size)
}

#[derive(Clone, Copy)]
struct TraceRecord {
    code: u8,
    timestamp: Time,
}

fn parse_queue(bytes: &[u8], offset: usize, name: &str) -> Result<(Vec<TraceRecord>, usize), KMError> {
    let size = queue_size(bytes, offset, name)?;
    let start = offset + 1;
    let end = start + size;
    let events = bytes[start..end]
        .chunks_exact(TRACE_RECORD_SIZE)
        .map(|record| TraceRecord {
            code: record[0],
            timestamp: Time::new::<second>(f64::from(u32::from_le_bytes([
                record[1], record[2], record[3], record[4],
            ]))),
        })
        .collect();
    Ok((events, end))
}

fn append_queue(
    bytes: &mut Vec<u8>,
    events: impl ExactSizeIterator<Item = TraceRecord>,
    name: &str,
) -> Result<(), KMError> {
    let size = events
        .len()
        .checked_mul(TRACE_RECORD_SIZE)
        .ok_or_else(|| KMError::InvalidPacket(format!("PD trace {name} queue length overflow")))?;
    if size > MAX_QUEUE_BYTES {
        return Err(KMError::InvalidPacket(format!(
            "PD trace {name} queue is too large: {size} bytes, maximum is {MAX_QUEUE_BYTES}"
        )));
    }

    bytes.push(size as u8);
    for event in events {
        bytes.push(event.code);
        bytes.extend_from_slice(&(event.timestamp.get::<second>() as u32).to_le_bytes());
    }
    Ok(())
}

#[cfg(feature = "python")]
#[pyo3::pymethods]
impl PdTraceStateEvent {
    #[getter]
    fn state_code(&self) -> u8 {
        self.state.into()
    }

    #[getter]
    fn state_name(&self) -> String {
        format!("{:?}", self.state)
    }

    #[getter]
    fn timestamp_seconds(&self) -> f64 {
        self.timestamp.get::<second>()
    }
}

#[cfg(feature = "python")]
#[pyo3::pymethods]
impl PdTraceProtocolEvent {
    #[getter]
    fn code(&self) -> u8 {
        self.kind.into()
    }

    #[getter]
    fn event_name(&self) -> String {
        format!("{:?}", self.kind)
    }

    #[getter]
    fn timestamp_seconds(&self) -> f64 {
        self.timestamp.get::<second>()
    }
}

#[cfg(feature = "python")]
#[pyo3::pymethods]
impl PdTrace {
    #[getter]
    fn state_events(&self) -> Vec<PdTraceStateEvent> {
        self.state_events.clone()
    }

    #[getter]
    fn protocol_events(&self) -> Vec<PdTraceProtocolEvent> {
        self.protocol_events.clone()
    }
}
