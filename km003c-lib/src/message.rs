use crate::adc::{AdcDataRaw, AdcDataSimple};
use crate::error::KMError;
use crate::packet::{Attribute, CtrlHeader, DataHeader, ExtendedHeader, PacketType, RawPacket};
use bytes::Bytes;
use zerocopy::{FromBytes, IntoBytes};

#[derive(Debug, Clone, PartialEq)]
pub enum Packet {
    /// Simple ADC data packet containing processed ADC readings
    SimpleAdcData {
        adc: AdcDataSimple,
        ext_payload: Option<Bytes>,
    },
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
                let payload_data = raw_packet.get_payload_data();
                let adc_raw_size = std::mem::size_of::<AdcDataRaw>();

                if payload_data.len() < adc_raw_size {
                    return Err(KMError::InvalidPacket(
                        "ADC payload too small".to_string(),
                    ));
                }

                let adc_data_raw = AdcDataRaw::ref_from_bytes(&payload_data[..adc_raw_size])
                    .unwrap(); // Should not fail due to size check

                let adc_data = AdcDataSimple::from(*adc_data_raw);

                let ext_payload = if payload_data.len() > adc_raw_size {
                    Some(payload_data.slice(adc_raw_size..))
                } else {
                    None
                };

                Ok(Packet::SimpleAdcData {
                    adc: adc_data,
                    ext_payload,
                })
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
            Packet::SimpleAdcData { adc, ext_payload } => {
                let adc_data_raw = AdcDataRaw::from(adc);
                let adc_bytes = adc_data_raw.as_bytes();

                let mut payload_buffer = adc_bytes.to_vec();
                if let Some(ext) = &ext_payload {
                    payload_buffer.extend_from_slice(ext);
                }

                let has_extension = ext_payload.is_some();
                let attribute_value: u16 = Attribute::Adc.into();

                let ext_header = ExtendedHeader::new()
                    .with_attribute(attribute_value)
                    .with_next(has_extension)
                    .with_chunk(0)
                    .with_size(adc_bytes.len() as u16); // Per docs, for ADC this is the size of the ADC payload

                let packet_type_value: u8 = PacketType::PutData.into();

                let header = DataHeader::new()
                    .with_packet_type(packet_type_value)
                    .with_extend(true)
                    .with_id(id)
                    .with_obj_count_words(((4 + payload_buffer.len()) / 4) as u16);

                RawPacket::ExtendedData {
                    header,
                    ext: ext_header,
                    payload: Bytes::from(payload_buffer),
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

                let packet_type_value: u8 = PacketType::PutData.into();

                let header = DataHeader::new()
                    .with_packet_type(packet_type_value)
                    .with_extend(true)
                    .with_id(id)
                    .with_obj_count_words(((4 + data.len()) / 4) as u16);

                RawPacket::ExtendedData {
                    header,
                    ext: ext_header,
                    payload: data,
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