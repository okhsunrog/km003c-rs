use crate::adc::{AdcDataRaw, AdcDataSimple};
use crate::constants::*;
use crate::error::KMError;
use crate::packet::{Attribute, AttributeSet, CtrlHeader, DataHeader, LogicalPacket, PacketType, RawPacket};
use crate::pd::{PdEventStream, PdStatus, PdStatusRaw};
use bytes::Bytes;
use num_enum::FromPrimitive;
use zerocopy::{FromBytes, IntoBytes};

/// Represents parsed payload data from logical packets
#[derive(Debug, Clone, PartialEq)]
pub enum PayloadData {
    Adc(AdcDataSimple),
    PdStatus(PdStatus),
    PdEvents(PdEventStream),
    Unknown { attribute: Attribute, data: Bytes },
}

#[derive(Debug, Clone, PartialEq)]
pub enum Packet {
    /// Data response with parsed payload data
    DataResponse(Vec<PayloadData>),
    /// Request data with attribute set
    GetData(AttributeSet),
    /// Accept response
    Accept { id: u8 },
    /// Connect command
    Connect,
    /// Disconnect command
    Disconnect,
    /// Generic packet for types we haven't specifically implemented yet
    Generic(RawPacket),
}

impl Packet {
    /// Get ADC data from the packet, if present
    pub fn get_adc(&self) -> Option<&AdcDataSimple> {
        match self {
            Self::DataResponse(payloads) => payloads.iter().find_map(|p| match p {
                PayloadData::Adc(adc) => Some(adc),
                _ => None,
            }),
            _ => None,
        }
    }

    /// Get PD status from the packet, if present
    pub fn get_pd_status(&self) -> Option<&PdStatus> {
        match self {
            Self::DataResponse(payloads) => payloads.iter().find_map(|p| match p {
                PayloadData::PdStatus(pd) => Some(pd),
                _ => None,
            }),
            _ => None,
        }
    }

    /// Get PD events from the packet, if present
    pub fn get_pd_events(&self) -> Option<&PdEventStream> {
        match self {
            Self::DataResponse(payloads) => payloads.iter().find_map(|p| match p {
                PayloadData::PdEvents(events) => Some(events),
                _ => None,
            }),
            _ => None,
        }
    }

    /// Check if packet has a specific payload type
    pub fn has_payload(&self, attr: Attribute) -> bool {
        match self {
            Self::DataResponse(payloads) => payloads.iter().any(|p| match p {
                PayloadData::Adc(_) => attr == Attribute::Adc,
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
                    PacketType::GetData => Ok(Packet::GetData(attribute_set)),
                    PacketType::Accept => Ok(Packet::Accept { id: header.id() }),
                    PacketType::Connect => Ok(Packet::Connect),
                    PacketType::Disconnect => Ok(Packet::Disconnect),
                    _ => Ok(Packet::Generic(RawPacket::Ctrl {
                        header,
                        payload: Bytes::new(),
                    })),
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
                                return Err(KMError::InvalidPacket(
                                    format!("ADC payload too small: expected {}, got {}", 
                                            ADC_DATA_SIZE, lp.payload.len())
                                ));
                            }

                            let adc_data_raw = AdcDataRaw::ref_from_bytes(&lp.payload[..ADC_DATA_SIZE])
                                .map_err(|_| KMError::InvalidPacket("Failed to parse ADC data".to_string()))?;
                            let adc_data = AdcDataSimple::from(*adc_data_raw);
                            PayloadData::Adc(adc_data)
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
                                let pd_events = PdEventStream::from_bytes(lp.payload)?;
                                PayloadData::PdEvents(pd_events)
                            }
                        }
                        _ => PayloadData::Unknown {
                            attribute: lp.attribute,
                            data: lp.payload,
                        },
                    };

                    payloads.push(payload_data);
                }

                Ok(Packet::DataResponse(payloads))
            }
            other => Ok(Packet::Generic(other)),
        }
    }
}

impl Packet {
    /// Convert a high-level packet to a raw packet with the given transaction ID
    pub fn to_raw_packet(self, id: u8) -> RawPacket {
        match self {
            Packet::DataResponse(payloads) => {
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
                                payload: Bytes::copy_from_slice(adc_raw.as_bytes()),
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
                                payload: Bytes::from(raw_bytes),
                            });
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
            Packet::GetData(attr_set) => RawPacket::Ctrl {
                header: CtrlHeader::new()
                    .with_packet_type(PacketType::GetData.into())
                    .with_reserved_flag(false)
                    .with_id(id)
                    .with_attribute(attr_set.raw()),
                payload: Bytes::new(),
            },
            Packet::Accept { id: accept_id } => RawPacket::Ctrl {
                header: CtrlHeader::new()
                    .with_packet_type(PacketType::Accept.into())
                    .with_reserved_flag(false)
                    .with_id(accept_id)
                    .with_attribute(0),
                payload: Bytes::new(),
            },
            Packet::Connect => RawPacket::Ctrl {
                header: CtrlHeader::new()
                    .with_packet_type(PacketType::Connect.into())
                    .with_reserved_flag(false)
                    .with_id(id)
                    .with_attribute(0),
                payload: Bytes::new(),
            },
            Packet::Disconnect => RawPacket::Ctrl {
                header: CtrlHeader::new()
                    .with_packet_type(PacketType::Disconnect.into())
                    .with_reserved_flag(false)
                    .with_id(id)
                    .with_attribute(0),
                payload: Bytes::new(),
            },
            Packet::Generic(raw_packet) => raw_packet,
        }
    }
}
