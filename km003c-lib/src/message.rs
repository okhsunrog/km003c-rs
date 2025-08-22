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
    /// Raw PD event stream from the device
    PdRawData(Bytes),
    /// Raw PD status stream (voltage/current updates)
    PdStatusData(Bytes),
    /// Command to request PD packet stream
    CmdGetPdData,
    /// Command to request PD status stream
    CmdGetPdStatus,
    /// Generic packet for types we haven't specifically implemented yet
    Generic(RawPacket),
}

impl TryFrom<RawPacket> for Packet {
    type Error = KMError;

    fn try_from(raw_packet: RawPacket) -> Result<Self, Self::Error> {
        // Use the new cleaner pattern with tuple matching
        match (raw_packet.packet_type(), raw_packet.get_attribute()) {
            (PacketType::PutData, Some(Attribute::Adc)) => {
                // Parse ADC data using payload (extended header already removed)
                let payload_data = raw_packet.payload();
                let adc_data_raw = AdcDataRaw::ref_from_bytes(payload_data.as_ref())
                    .map_err(|_| KMError::InvalidPacket("Failed to parse ADC data: incorrect size".to_string()))?;

                // Convert to user-friendly format
                let adc_data = AdcDataSimple::from(*adc_data_raw);

                Ok(Packet::SimpleAdcData(adc_data))
            }
            (PacketType::PutData, Some(Attribute::PdPacket)) => {
                let payload_data = raw_packet.payload();
                Ok(Packet::PdRawData(payload_data))
            }
            (PacketType::PutData, Some(Attribute::PdStatus)) => {
                let payload_data = raw_packet.payload();
                Ok(Packet::PdStatusData(payload_data))
            }
            (PacketType::GetData, Some(Attribute::Adc)) => {
                // ADC request command
                Ok(Packet::CmdGetSimpleAdcData)
            }
            (PacketType::GetData, Some(Attribute::PdPacket)) => Ok(Packet::CmdGetPdData),
            (PacketType::GetData, Some(Attribute::PdStatus)) => Ok(Packet::CmdGetPdStatus),
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

                // Use the IntoPrimitive trait to convert the enum to its primitive value
                let packet_type_value: u8 = PacketType::PutData.into();

                let header = DataHeader::new()
                    .with_packet_type(packet_type_value)
                    .with_flag(true)
                    .with_id(id)
                    .with_obj_count_words(0); // This might need adjustment

                RawPacket::Data {
                    header,
                    extended: ext_header,
                    payload: Bytes::from(buffer),
                }
            }
            Packet::CmdGetSimpleAdcData => RawPacket::Ctrl {
                header: CtrlHeader::new()
                    .with_packet_type(PacketType::GetData.into())
                    .with_flag(false)
                    .with_id(id)
                    .with_attribute(Attribute::Adc.into()),
                payload: Bytes::new(),
            },
            Packet::PdRawData(data) => {
                let attribute_value: u16 = Attribute::PdPacket.into();
                build_put_data_packet(id, attribute_value, data)
            }
            Packet::PdStatusData(data) => {
                let attribute_value: u16 = Attribute::PdStatus.into();
                build_put_data_packet(id, attribute_value, data)
            }
            Packet::CmdGetPdData => RawPacket::Ctrl {
                header: CtrlHeader::new()
                    .with_packet_type(PacketType::GetData.into())
                    .with_flag(false)
                    .with_id(id)
                    .with_attribute(Attribute::PdPacket.into()),
                payload: Bytes::new(),
            },
            Packet::CmdGetPdStatus => RawPacket::Ctrl {
                header: CtrlHeader::new()
                    .with_packet_type(PacketType::GetData.into())
                    .with_flag(false)
                    .with_id(id)
                    .with_attribute(Attribute::PdStatus.into()),
                payload: Bytes::new(),
            },
            Packet::Generic(raw_packet) => raw_packet,
        }
    }
}

/// Helper to build a `PutData` packet with an extended header
fn build_put_data_packet(id: u8, attribute: u16, data: Bytes) -> RawPacket {
    let ext_header = ExtendedHeader::new()
        .with_attribute(attribute)
        .with_next(false)
        .with_chunk(0)
        .with_size(data.len() as u16);

    let packet_type_value: u8 = PacketType::PutData.into();
    let header = DataHeader::new()
        .with_packet_type(packet_type_value)
        .with_flag(true)
        .with_id(id)
        .with_obj_count_words(0);

    RawPacket::Data {
        header,
        extended: ext_header,
        payload: data,
    }
}
