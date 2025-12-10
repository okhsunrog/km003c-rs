use crate::adc::{AdcDataRaw, AdcDataSimple};
use crate::adcqueue::AdcQueueData;
use crate::auth::{self, HardwareId, StreamingAuthResult};
use crate::constants::*;
use crate::error::KMError;
use crate::packet::{Attribute, AttributeSet, CtrlHeader, DataHeader, LogicalPacket, PacketType, RawPacket};
use crate::pd::{PdEventStream, PdStatus, PdStatusRaw};
use bytes::Bytes;
use num_enum::FromPrimitive;
use zerocopy::{FromBytes, IntoBytes};

/// Represents parsed payload data from logical packets
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "python", derive(pyo3::IntoPyObject))]
pub enum PayloadData {
    Adc(AdcDataSimple),
    AdcQueue(AdcQueueData),
    PdStatus(PdStatus),
    PdEvents(PdEventStream),
    Unknown { attribute: Attribute, data: Vec<u8> },
}

#[derive(Debug, Clone, PartialEq)]
pub enum Packet {
    /// Data response with parsed payload data
    DataResponse { payloads: Vec<PayloadData> },
    /// Request data with attribute set
    GetData { attribute_mask: u16 },
    /// Start AdcQueue graph mode with sample rate
    /// Rate byte: 0=2SPS, 2=10SPS, 4=50SPS, 6=1000SPS (device uses bits 1-2)
    StartGraph { rate_index: u16 },
    /// Stop AdcQueue graph mode
    StopGraph,
    /// Accept response
    Accept { id: u8 },
    /// Connect command
    Connect,
    /// Disconnect command
    Disconnect,
    /// Enable PD monitor/sniffer
    EnablePdMonitor,
    /// Disable PD monitor/sniffer
    DisablePdMonitor,
    /// MemoryRead command (0x44) - read device memory with encrypted payload
    MemoryRead {
        /// Memory address to read from
        address: u32,
        /// Number of bytes to read
        size: u32,
    },
    /// MemoryRead response (0x75) - raw data from device memory
    MemoryReadResponse {
        /// Raw data read from memory (e.g., 12-byte HardwareID)
        data: Vec<u8>,
    },
    /// StreamingAuth command (0x4C) - authenticate for AdcQueue streaming
    StreamingAuth {
        /// HardwareID to authenticate with
        hardware_id: HardwareId,
    },
    /// StreamingAuth response (0xCC) - authentication result
    StreamingAuthResponse(StreamingAuthResult),
    /// Generic packet for types we haven't specifically implemented yet
    Generic(RawPacket),
}

impl Packet {
    /// Get ADC data from the packet, if present
    pub fn get_adc(&self) -> Option<&AdcDataSimple> {
        match self {
            Self::DataResponse { payloads } => payloads.iter().find_map(|p| match p {
                PayloadData::Adc(adc) => Some(adc),
                _ => None,
            }),
            _ => None,
        }
    }

    /// Get AdcQueue data from the packet, if present
    pub fn get_adc_queue(&self) -> Option<&AdcQueueData> {
        match self {
            Self::DataResponse { payloads } => payloads.iter().find_map(|p| match p {
                PayloadData::AdcQueue(queue) => Some(queue),
                _ => None,
            }),
            _ => None,
        }
    }

    /// Get PD status from the packet, if present
    pub fn get_pd_status(&self) -> Option<&PdStatus> {
        match self {
            Self::DataResponse { payloads } => payloads.iter().find_map(|p| match p {
                PayloadData::PdStatus(pd) => Some(pd),
                _ => None,
            }),
            _ => None,
        }
    }

    /// Get PD events from the packet, if present
    pub fn get_pd_events(&self) -> Option<&PdEventStream> {
        match self {
            Self::DataResponse { payloads } => payloads.iter().find_map(|p| match p {
                PayloadData::PdEvents(events) => Some(events),
                _ => None,
            }),
            _ => None,
        }
    }

    /// Check if packet has a specific payload type
    pub fn has_payload(&self, attr: Attribute) -> bool {
        match self {
            Self::DataResponse { payloads } => payloads.iter().any(|p| match p {
                PayloadData::Adc(_) => attr == Attribute::Adc,
                PayloadData::AdcQueue(_) => attr == Attribute::AdcQueue,
                PayloadData::PdStatus(_) | PayloadData::PdEvents(_) => attr == Attribute::PdPacket,
                PayloadData::Unknown { attribute, .. } => *attribute == attr,
            }),
            _ => false,
        }
    }
}

impl TryFrom<RawPacket> for Packet {
    type Error = KMError;

    fn try_from(raw_packet: RawPacket) -> Result<Self, Self::Error> {
        match raw_packet {
            RawPacket::Ctrl { header, .. } => {
                let packet_type = PacketType::from_primitive(header.packet_type());
                let attribute_set = AttributeSet::from_raw(header.attribute());

                match packet_type {
                    PacketType::GetData => Ok(Packet::GetData {
                        attribute_mask: attribute_set.raw(),
                    }),
                    PacketType::StartGraph => Ok(Packet::StartGraph {
                        rate_index: attribute_set.raw(),
                    }),
                    PacketType::StopGraph => Ok(Packet::StopGraph),
                    PacketType::Accept => Ok(Packet::Accept { id: header.id() }),
                    PacketType::Connect => Ok(Packet::Connect),
                    PacketType::Disconnect => Ok(Packet::Disconnect),
                    _ => Ok(Packet::Generic(RawPacket::Ctrl {
                        header,
                        payload: Vec::new(),
                    })),
                }
            }
            RawPacket::SimpleData { header, payload } => {
                let packet_type = PacketType::from_primitive(header.packet_type());

                match packet_type {
                    // MemoryReadResponse (0x75) - contains raw data from device memory
                    // Format: [type:1][data:N] - NOT a 4-byte header
                    PacketType::MemoryReadResponse => {
                        // Data starts at byte 1 (after the type byte which is in header)
                        Ok(Packet::MemoryReadResponse { data: payload.to_vec() })
                    }
                    // MemoryRead response (0xC4 = 0x44 | 0x80) - confirmation
                    PacketType::MemoryRead => {
                        // This is just a confirmation, return as Accept-like
                        Ok(Packet::Accept { id: header.id() })
                    }
                    // StreamingAuth response (0xCC = 0x4C | 0x80) - encrypted result
                    PacketType::StreamingAuth => {
                        if payload.len() >= 32 {
                            if let Some(result) = auth::parse_streaming_auth_response_payload(&payload) {
                                Ok(Packet::StreamingAuthResponse(result))
                            } else {
                                Ok(Packet::Generic(RawPacket::SimpleData { header, payload }))
                            }
                        } else {
                            Ok(Packet::Generic(RawPacket::SimpleData { header, payload }))
                        }
                    }
                    _ => Ok(Packet::Generic(RawPacket::SimpleData { header, payload })),
                }
            }
            RawPacket::Data { logical_packets, .. } => {
                // Parse logical packets into PayloadData
                let mut payloads = Vec::new();

                for lp in logical_packets {
                    let payload_data = match lp.attribute {
                        Attribute::Adc => {
                            // Parse ADC data (44 bytes)
                            if lp.payload.len() < ADC_DATA_SIZE {
                                return Err(KMError::InvalidPacket(format!(
                                    "ADC payload too small: expected {}, got {}",
                                    ADC_DATA_SIZE,
                                    lp.payload.len()
                                )));
                            }

                            let adc_data_raw = AdcDataRaw::ref_from_bytes(&lp.payload[..ADC_DATA_SIZE])
                                .map_err(|_| KMError::InvalidPacket("Failed to parse ADC data".to_string()))?;
                            let adc_data = AdcDataSimple::from(*adc_data_raw);
                            PayloadData::Adc(adc_data)
                        }
                        Attribute::AdcQueue => {
                            // Parse AdcQueue data (multiple 20-byte samples)
                            // Note: Extended header size field (typically 20) indicates size per sample,
                            // not total payload size. Actual payload contains N samples.
                            let adcqueue = AdcQueueData::from_bytes(lp.payload.as_ref())?;
                            PayloadData::AdcQueue(adcqueue)
                        }
                        Attribute::PdPacket => {
                            // Determine if this is PD status or PD events
                            if lp.payload.len() == PD_STATUS_SIZE {
                                // PD Status (12 bytes)
                                let pd_status_raw = PdStatusRaw::ref_from_bytes(lp.payload.as_ref())
                                    .map_err(|_| KMError::InvalidPacket("Failed to parse PD status".to_string()))?;
                                PayloadData::PdStatus(PdStatus::from(*pd_status_raw))
                            } else {
                                // PD Event Stream
                                let pd_events = PdEventStream::from_bytes(Bytes::from(lp.payload))?;
                                PayloadData::PdEvents(pd_events)
                            }
                        }
                        _ => PayloadData::Unknown {
                            attribute: lp.attribute,
                            data: lp.payload.to_vec(),
                        },
                    };

                    payloads.push(payload_data);
                }

                Ok(Packet::DataResponse { payloads })
            }
        }
    }
}

impl Packet {
    /// Convert a high-level packet to a raw packet with the given transaction ID
    pub fn to_raw_packet(self, id: u8) -> RawPacket {
        match self {
            Packet::DataResponse { payloads } => {
                // Convert PayloadData vec to LogicalPackets
                let mut logical_packets = Vec::new();

                for (i, payload) in payloads.into_iter().enumerate() {
                    let is_last = i == logical_packets.len();

                    match payload {
                        PayloadData::Adc(adc) => {
                            let adc_raw = AdcDataRaw::from(adc);
                            logical_packets.push(LogicalPacket {
                                attribute: Attribute::Adc,
                                next: !is_last,
                                chunk: 0,
                                size: ADC_DATA_SIZE as u16,
                                payload: adc_raw.as_bytes().to_vec(),
                            });
                        }
                        PayloadData::PdStatus(pd_status) => {
                            // Reconstruct PdStatusRaw
                            let timestamp_bytes = pd_status.timestamp.to_le_bytes();
                            let mut raw_bytes = Vec::with_capacity(12);
                            raw_bytes.push(pd_status.type_id);
                            raw_bytes.extend_from_slice(&timestamp_bytes[..3]); // 24-bit
                            raw_bytes.extend_from_slice(&((pd_status.vbus_v * 1000.0) as u16).to_le_bytes());
                            raw_bytes.extend_from_slice(&((pd_status.ibus_a * 1000.0) as u16).to_le_bytes());
                            raw_bytes.extend_from_slice(&((pd_status.cc1_v * 1000.0) as u16).to_le_bytes());
                            raw_bytes.extend_from_slice(&((pd_status.cc2_v * 1000.0) as u16).to_le_bytes());

                            logical_packets.push(LogicalPacket {
                                attribute: Attribute::PdPacket,
                                next: !is_last,
                                chunk: 0,
                                size: PD_STATUS_SIZE as u16,
                                payload: raw_bytes,
                            });
                        }
                        PayloadData::AdcQueue(_adcqueue) => {
                            // TODO: Implement AdcQueue serialization
                            // For now, skip this
                            continue;
                        }
                        PayloadData::PdEvents(_pd_events) => {
                            // TODO: Implement PdEventStream serialization
                            // For now, skip this
                            continue;
                        }
                        PayloadData::Unknown { attribute, data } => {
                            logical_packets.push(LogicalPacket {
                                attribute,
                                next: !is_last,
                                chunk: 0,
                                size: data.len() as u16,
                                payload: data,
                            });
                        }
                    }
                }

                // Calculate total payload size
                let total_size: usize = logical_packets.iter().map(|lp| 4 + lp.payload.len()).sum();

                let header = DataHeader::new()
                    .with_packet_type(PacketType::PutData.into())
                    .with_reserved_flag(true)
                    .with_id(id)
                    .with_obj_count_words((total_size / 4) as u16);

                RawPacket::Data {
                    header,
                    logical_packets,
                }
            }
            Packet::GetData { attribute_mask } => RawPacket::Ctrl {
                header: CtrlHeader::new()
                    .with_packet_type(PacketType::GetData.into())
                    .with_reserved_flag(false)
                    .with_id(id)
                    .with_attribute(attribute_mask),
                payload: Vec::new(),
            },
            Packet::StartGraph { rate_index } => RawPacket::Ctrl {
                header: CtrlHeader::new()
                    .with_packet_type(PacketType::StartGraph.into())
                    .with_reserved_flag(false)
                    .with_id(id)
                    .with_attribute(rate_index),
                payload: Vec::new(),
            },
            Packet::StopGraph => RawPacket::Ctrl {
                header: CtrlHeader::new()
                    .with_packet_type(PacketType::StopGraph.into())
                    .with_reserved_flag(false)
                    .with_id(id)
                    .with_attribute(0),
                payload: Vec::new(),
            },
            Packet::Accept { id: accept_id } => RawPacket::Ctrl {
                header: CtrlHeader::new()
                    .with_packet_type(PacketType::Accept.into())
                    .with_reserved_flag(false)
                    .with_id(accept_id)
                    .with_attribute(0),
                payload: Vec::new(),
            },
            Packet::Connect => RawPacket::Ctrl {
                header: CtrlHeader::new()
                    .with_packet_type(PacketType::Connect.into())
                    .with_reserved_flag(false)
                    .with_id(id)
                    .with_attribute(0),
                payload: Vec::new(),
            },
            Packet::Disconnect => RawPacket::Ctrl {
                header: CtrlHeader::new()
                    .with_packet_type(PacketType::Disconnect.into())
                    .with_reserved_flag(false)
                    .with_id(id)
                    .with_attribute(0),
                payload: Vec::new(),
            },
            // EnablePdMonitor: attribute 0x0002 is the fixed protocol value for enabling PD capture.
            // Future: could make this configurable via EnablePdMonitor { attribute: u16 } if needed.
            Packet::EnablePdMonitor => RawPacket::Ctrl {
                header: CtrlHeader::new()
                    .with_packet_type(PacketType::EnablePdMonitor.into())
                    .with_reserved_flag(false)
                    .with_id(id)
                    .with_attribute(0x0002),
                payload: Vec::new(),
            },
            // DisablePdMonitor: attribute 0x0000 is the fixed protocol value for disabling PD capture.
            // Future: could make this configurable via DisablePdMonitor { attribute: u16 } if needed.
            Packet::DisablePdMonitor => RawPacket::Ctrl {
                header: CtrlHeader::new()
                    .with_packet_type(PacketType::DisablePdMonitor.into())
                    .with_reserved_flag(false)
                    .with_id(id)
                    .with_attribute(0x0000),
                payload: Vec::new(),
            },
            Packet::MemoryRead { address, size } => {
                // Build encrypted MemoryRead payload
                let encrypted_payload = auth::build_memory_read_payload(address, size);
                RawPacket::SimpleData {
                    header: DataHeader::new()
                        .with_packet_type(PacketType::MemoryRead.into())
                        .with_reserved_flag(false)
                        .with_id(id)
                        .with_obj_count_words(0x0101), // Attribute for MemoryRead
                    payload: encrypted_payload.to_vec(),
                }
            }
            Packet::MemoryReadResponse { data } => {
                // Response packets are typically not sent by client, but support for completeness
                RawPacket::SimpleData {
                    header: DataHeader::new()
                        .with_packet_type(PacketType::MemoryReadResponse.into())
                        .with_reserved_flag(false)
                        .with_id(id)
                        .with_obj_count_words(0),
                    payload: data,
                }
            }
            Packet::StreamingAuth { hardware_id } => {
                // Build encrypted StreamingAuth payload
                let encrypted_payload = auth::build_streaming_auth_payload(&hardware_id);
                RawPacket::SimpleData {
                    header: DataHeader::new()
                        .with_packet_type(PacketType::StreamingAuth.into())
                        .with_reserved_flag(false)
                        .with_id(id)
                        .with_obj_count_words(0x0200), // Attribute for StreamingAuth
                    payload: encrypted_payload.to_vec(),
                }
            }
            Packet::StreamingAuthResponse(result) => {
                // Response packets are typically not sent by client, but support for completeness
                let encrypted_payload = auth::encrypt_streaming_auth_payload(&result.decrypted_payload);
                RawPacket::SimpleData {
                    header: DataHeader::new()
                        .with_packet_type(PacketType::StreamingAuth.into())
                        .with_reserved_flag(true) // Response has high bit set
                        .with_id(id)
                        .with_obj_count_words(result.attribute),
                    payload: encrypted_payload.to_vec(),
                }
            }
            Packet::Generic(raw_packet) => raw_packet,
        }
    }
}

// Python support for Packet
#[cfg(feature = "python")]
impl<'py> pyo3::IntoPyObject<'py> for Packet {
    type Target = pyo3::PyAny;
    type Output = pyo3::Bound<'py, Self::Target>;
    type Error = pyo3::PyErr;

    fn into_pyobject(self, py: pyo3::Python<'py>) -> Result<Self::Output, Self::Error> {
        use pyo3::types::{PyDict, PyDictMethods};

        let dict = PyDict::new(py);
        match self {
            Packet::DataResponse { payloads } => {
                let inner = PyDict::new(py);
                inner.set_item("payloads", payloads.into_pyobject(py)?)?;
                dict.set_item("DataResponse", inner)?;
            }
            Packet::GetData { attribute_mask } => {
                let inner = PyDict::new(py);
                inner.set_item("attribute_mask", attribute_mask)?;
                dict.set_item("GetData", inner)?;
            }
            Packet::StartGraph { rate_index } => {
                let inner = PyDict::new(py);
                inner.set_item("rate_index", rate_index)?;
                dict.set_item("StartGraph", inner)?;
            }
            Packet::StopGraph => {
                dict.set_item("StopGraph", py.None())?;
            }
            Packet::Accept { id } => {
                let inner = PyDict::new(py);
                inner.set_item("id", id)?;
                dict.set_item("Accept", inner)?;
            }
            Packet::Connect => {
                dict.set_item("Connect", py.None())?;
            }
            Packet::Disconnect => {
                dict.set_item("Disconnect", py.None())?;
            }
            Packet::Generic(raw_packet) => {
                dict.set_item("Generic", raw_packet.into_pyobject(py)?)?;
            }
        }
        Ok(dict.into_any())
    }
}
