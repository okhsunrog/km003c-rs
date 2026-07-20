//! Stateful semantic decoding of USB Power Delivery events.
//!
//! The KM003C-specific framing parser in [`crate::pd`] extracts standard USB PD
//! wire messages. This module optionally decodes those messages through the
//! `usbpd` crate while retaining the source capabilities and extended-message
//! assembly state needed across events.

use thiserror::Error;
use uom::si::f64::Time;
use usbpd::protocol_layer::message::data::Data;
use usbpd::protocol_layer::message::data::source_capabilities::SourceCapabilities;
use usbpd::protocol_layer::message::extended::chunked::{ChunkResult, ChunkedMessageAssembler};
use usbpd::protocol_layer::message::header::{ExtendedMessageType, Header, MessageType};
use usbpd::protocol_layer::message::{Message, ParseError, Payload};

use crate::pd::{PdEvent, PdEventData};

/// A semantically decoded USB PD message with its KM003C capture metadata.
#[derive(Debug, Clone)]
pub struct DecodedPdMessage {
    pub timestamp: Time,
    pub sop: u8,
    pub message: Message,
}

/// Progress reported while handling a chunked USB PD extended message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdChunkState {
    Request { chunk_number: u8 },
    Pending { received_chunk: u8, next_chunk: u8 },
    Requested { chunk_number: u8 },
    Unsupported { chunk_number: u8, data_size: u16 },
}

/// A chunked-message state change with its KM003C capture metadata.
#[derive(Debug, Clone, Copy)]
pub struct PdChunkStatus {
    pub timestamp: Time,
    pub sop: u8,
    pub message_type: ExtendedMessageType,
    pub state: PdChunkState,
}

/// Errors produced while semantically decoding an extracted USB PD message.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PdDecodeError {
    #[error("USB PD wire message is empty")]
    EmptyMessage,
    #[error(transparent)]
    Parse(#[from] ParseError),
}

/// A semantic decoding failure with the original wire bytes.
#[derive(Debug, Clone)]
pub struct PdDecodeFailure {
    pub timestamp: Time,
    pub sop: u8,
    pub error: PdDecodeError,
    pub wire_data: Vec<u8>,
}

/// Result of decoding one KM003C PD event.
#[derive(Debug, Clone)]
pub enum DecodedPdEvent {
    Connect { timestamp: Time },
    Disconnect { timestamp: Time },
    Message(DecodedPdMessage),
    Chunk(PdChunkStatus),
    Error(PdDecodeFailure),
}

/// Stateful decoder for a sequence of KM003C USB PD events.
///
/// The decoder remembers SPR source capabilities so that subsequent Request
/// messages can be interpreted using the selected PDO type. It also assembles
/// chunked EPR Source Capabilities messages.
#[derive(Debug, Clone, Default)]
pub struct PdSessionDecoder {
    source_capabilities: Option<SourceCapabilities>,
    epr_assembler: ChunkedMessageAssembler,
}

#[derive(Debug, Clone, Copy)]
struct ChunkDescriptor {
    number: u8,
    data_size: u16,
    request: bool,
    message_type: ExtendedMessageType,
}

impl PdSessionDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Clear all connection-specific decoding state.
    pub fn reset(&mut self) {
        self.source_capabilities = None;
        self.epr_assembler.reset();
    }

    /// Most recently observed SPR source capabilities.
    pub fn source_capabilities(&self) -> Option<&SourceCapabilities> {
        self.source_capabilities.as_ref()
    }

    /// Decode one KM003C PD event.
    pub fn decode_event(&mut self, event: &PdEvent) -> DecodedPdEvent {
        match &event.data {
            PdEventData::Connect(()) => {
                self.reset();
                DecodedPdEvent::Connect {
                    timestamp: event.timestamp,
                }
            }
            PdEventData::Disconnect(()) => DecodedPdEvent::Disconnect {
                timestamp: event.timestamp,
            },
            PdEventData::PdMessage { sop, wire_data } => self.decode_message(event.timestamp, *sop, wire_data),
        }
    }

    fn decode_message(&mut self, timestamp: Time, sop: u8, wire_data: &[u8]) -> DecodedPdEvent {
        if wire_data.is_empty() {
            return self.failure(timestamp, sop, PdDecodeError::EmptyMessage, wire_data);
        }

        match parse_message_with_state(wire_data, self.source_capabilities.as_ref()) {
            Ok(message) => {
                if let Some(Payload::Data(Data::SourceCapabilities(capabilities))) = &message.payload {
                    self.source_capabilities = Some(capabilities.clone());
                }

                DecodedPdEvent::Message(DecodedPdMessage {
                    timestamp,
                    sop,
                    message,
                })
            }
            Err(ParseError::ChunkedExtendedMessage {
                chunk_number,
                data_size,
                request_chunk,
                message_type,
            }) => self.decode_chunk(
                timestamp,
                sop,
                wire_data,
                ChunkDescriptor {
                    number: chunk_number,
                    data_size,
                    request: request_chunk,
                    message_type,
                },
            ),
            Err(error) => self.failure(timestamp, sop, error.into(), wire_data),
        }
    }

    fn decode_chunk(&mut self, timestamp: Time, sop: u8, wire_data: &[u8], chunk: ChunkDescriptor) -> DecodedPdEvent {
        if chunk.request {
            return DecodedPdEvent::Chunk(PdChunkStatus {
                timestamp,
                sop,
                message_type: chunk.message_type,
                state: PdChunkState::Request {
                    chunk_number: chunk.number,
                },
            });
        }

        if chunk.message_type != ExtendedMessageType::EprSourceCapabilities {
            return DecodedPdEvent::Chunk(PdChunkStatus {
                timestamp,
                sop,
                message_type: chunk.message_type,
                state: PdChunkState::Unsupported {
                    chunk_number: chunk.number,
                    data_size: chunk.data_size,
                },
            });
        }

        let (header, extended_header, chunk_data) = match Message::parse_extended_chunk(wire_data) {
            Ok(parts) => parts,
            Err(error) => return self.failure(timestamp, sop, error.into(), wire_data),
        };

        match self.epr_assembler.process_chunk(header, extended_header, chunk_data) {
            Ok(ChunkResult::Complete(data)) => {
                let payload = Message::parse_extended_payload(chunk.message_type, &data);
                DecodedPdEvent::Message(DecodedPdMessage {
                    timestamp,
                    sop,
                    message: Message {
                        header,
                        payload: Some(Payload::Extended(payload)),
                    },
                })
            }
            Ok(ChunkResult::NeedMoreChunks(next_chunk)) => DecodedPdEvent::Chunk(PdChunkStatus {
                timestamp,
                sop,
                message_type: chunk.message_type,
                state: PdChunkState::Pending {
                    received_chunk: chunk.number,
                    next_chunk,
                },
            }),
            Ok(ChunkResult::ChunkRequested(chunk_number)) => DecodedPdEvent::Chunk(PdChunkStatus {
                timestamp,
                sop,
                message_type: chunk.message_type,
                state: PdChunkState::Requested { chunk_number },
            }),
            Err(error) => {
                self.epr_assembler.reset();
                self.failure(timestamp, sop, error.into(), wire_data)
            }
        }
    }

    fn failure(&self, timestamp: Time, sop: u8, error: PdDecodeError, wire_data: &[u8]) -> DecodedPdEvent {
        DecodedPdEvent::Error(PdDecodeFailure {
            timestamp,
            sop,
            error,
            wire_data: wire_data.to_vec(),
        })
    }
}

fn parse_message_with_state(
    wire_data: &[u8],
    source_capabilities: Option<&SourceCapabilities>,
) -> Result<Message, ParseError> {
    if wire_data.len() < 2 {
        return Err(ParseError::InvalidLength {
            expected: 2,
            found: wire_data.len(),
        });
    }

    let header = Header::from_bytes(&wire_data[..2])?;
    let message = Message::new(header);

    match header.message_type() {
        MessageType::Data(message_type) => {
            Data::parse_message(message, message_type, &wire_data[2..], &source_capabilities)
        }
        _ => Message::from_bytes(wire_data),
    }
}
