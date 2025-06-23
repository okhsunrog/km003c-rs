use crate::adc::{AdcDataRaw, AdcDataSimple};
use crate::error::KMError;
use crate::packet::{Attribute, CtrlHeader, DataHeader, ExtendedHeader, PacketType, RawPacket};
use bytes::Bytes;
use zerocopy::{FromBytes, IntoBytes};

#[derive(Debug, Clone, PartialEq)]
pub enum Packet {
    /// Simple ADC data packet containing processed ADC readings
    SimpleAdcData(AdcDataSimple),
    /// Command to request simple ADC data
    CmdGetSimpleAdcData,
    /// Raw PD data packet containing unprocessed PD packet bytes
    PdRawData(Bytes),
    /// Command to request PD data
    CmdGetPdData,
    /// Generic packet for types we haven't specifically implemented yet
    Generic(RawPacket),
}

impl TryFrom<RawPacket> for Packet {
    type Error = KMError;

    fn try_from(raw_packet: RawPacket) -> Result<Self, Self::Error> {
        // Use the new cleaner pattern with tuple matching
        match (raw_packet.packet_type(), raw_packet.get_attribute()) {
            (PacketType::PutData, Some(Attribute::Adc)) => {
                // Parse ADC data using clean payload data
                let payload_data = raw_packet.get_payload_data();
                let adc_data_raw = AdcDataRaw::ref_from_bytes(payload_data.as_ref())
                    .map_err(|_| KMError::InvalidPacket("Failed to parse ADC data: incorrect size".to_string()))?;

                // Convert to user-friendly format
                let adc_data = AdcDataSimple::from(*adc_data_raw);

                Ok(Packet::SimpleAdcData(adc_data))
            }
            (PacketType::PutData, Some(Attribute::PdPacket)) => {
                // Parse PD data - just return raw payload bytes
                let payload_data = raw_packet.get_payload_data();
                Ok(Packet::PdRawData(payload_data))
            }
            (PacketType::GetData, Some(Attribute::Adc)) => {
                // ADC request command
                Ok(Packet::CmdGetSimpleAdcData)
            }
            (PacketType::GetData, Some(Attribute::PdPacket)) => {
                // PD request command
                Ok(Packet::CmdGetPdData)
            }
            _ => {
                // If we don't recognize the packet type or can't parse it, return it as Generic
                Ok(Packet::Generic(raw_packet))
            }
        }
    }
}

impl Packet {
    /// Convert a high-level packet to a raw packet with the given transaction ID
    pub fn to_raw_packet(self, id: u8) -> RawPacket {
        match self {
            Packet::SimpleAdcData(adc_data) => {
                // Convert AdcDataSimple to AdcDataRaw
                let adc_data_raw = AdcDataRaw::from(adc_data);

                // Create a buffer to hold the ADC data
                let buffer = adc_data_raw.as_bytes().to_vec();

                // Get the attribute value directly
                let attribute_value: u16 = Attribute::Adc.into();

                let ext_header = ExtendedHeader::new()
                    .with_attribute(attribute_value)
                    .with_next(false)
                    .with_chunk(0)
                    .with_size(buffer.len() as u16);

                // Prepend the extended header to the buffer
                let mut full_payload = Vec::new();
                full_payload.extend_from_slice(&ext_header.into_bytes());
                full_payload.extend_from_slice(&buffer);

                // Use the IntoPrimitive trait to convert the enum to its primitive value
                let packet_type_value: u8 = PacketType::PutData.into();

                let header = DataHeader::new()
                    .with_packet_type(packet_type_value)
                    .with_extend(true)
                    .with_id(id)
                    .with_obj_count_words(0); // This might need adjustment

                RawPacket::Data {
                    header,
                    payload: Bytes::from(full_payload),
                }
            }
            Packet::CmdGetSimpleAdcData => RawPacket::Ctrl {
                header: CtrlHeader::new()
                    .with_packet_type(PacketType::GetData.into())
                    .with_extend(false)
                    .with_id(id)
                    .with_attribute(Attribute::Adc.into()),
                payload: Bytes::new(),
            },
            Packet::PdRawData(data) => {
                // Create PD data packet with extended header
                let attribute_value: u16 = Attribute::PdPacket.into();

                let ext_header = ExtendedHeader::new()
                    .with_attribute(attribute_value)
                    .with_next(false)
                    .with_chunk(0)
                    .with_size(data.len() as u16);

                // Prepend the extended header to the data
                let mut full_payload = Vec::new();
                full_payload.extend_from_slice(&ext_header.into_bytes());
                full_payload.extend_from_slice(&data);

                let packet_type_value: u8 = PacketType::PutData.into();

                let header = DataHeader::new()
                    .with_packet_type(packet_type_value)
                    .with_extend(true)
                    .with_id(id)
                    .with_obj_count_words(0);

                RawPacket::Data {
                    header,
                    payload: Bytes::from(full_payload),
                }
            }
            Packet::CmdGetPdData => RawPacket::Ctrl {
                header: CtrlHeader::new()
                    .with_packet_type(PacketType::GetData.into())
                    .with_extend(false)
                    .with_id(id)
                    .with_attribute(Attribute::PdPacket.into()),
                payload: Bytes::new(),
            },
            Packet::Generic(raw_packet) => raw_packet,
        }
    }
}
