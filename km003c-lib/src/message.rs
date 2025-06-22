use crate::adc::{AdcDataRaw, AdcDataSimple, SampleRate};
use crate::error::KMError;
use crate::packet::{Attribute, CtrlHeader, DataHeader, ExtendedHeader, PacketType, RawPacket};
use bytes::Bytes;
use num_enum::FromPrimitive;
use zerocopy::{FromBytes, IntoBytes};

#[derive(Debug, Clone, PartialEq)]
pub enum Packet {
    /// Simple ADC data packet containing processed ADC readings
    SimpleAdcData(AdcDataSimple),
    /// Command to request simple ADC data
    CmdGetSimpleAdcData,
    /// Generic packet for types we haven't specifically implemented yet
    Generic(RawPacket),
}

impl Packet {
    /// Create a new SimpleAdcData packet
    pub fn new_simple_adc_data(adc_data: AdcDataSimple) -> Self {
        Packet::SimpleAdcData(adc_data)
    }

    /// Create a packet to set the sample rate
    pub fn new_set_sample_rate(_id: u8, _rate: SampleRate) -> Self {
        // This would create a packet to set the sample rate
        // We'll implement this later when we know more about the protocol
        todo!("Implement set sample rate packet")
    }
}

impl TryFrom<RawPacket> for Packet {
    type Error = KMError;

    fn try_from(mut raw_packet: RawPacket) -> Result<Self, Self::Error> {
        // Check if this is an ADC data packet
        if raw_packet.packet_type() == PacketType::PutData && has_extended_header(&raw_packet) {
            let ext_header = raw_packet.get_ext_header()?;

            // Check if this is a simple ADC data packet
            if Attribute::from_primitive(ext_header.attribute()) == Attribute::Adc {
                // Parse the payload as AdcDataRaw using zerocopy
                let payload_bytes = raw_packet.payload();
                let adc_data_raw = AdcDataRaw::ref_from_bytes(payload_bytes.as_ref())
                    .map_err(|_| KMError::InvalidPacket("Failed to parse ADC data: incorrect size".to_string()))?;

                // Convert to user-friendly format
                let adc_data = AdcDataSimple::from(*adc_data_raw);

                return Ok(Packet::SimpleAdcData(adc_data));
            }
        }

        // If we don't recognize the packet type or can't parse it, return it as Generic
        Ok(Packet::Generic(raw_packet))
    }
}

impl Packet {
    /// Convert a high-level packet to a raw packet with the given transaction ID
    pub(crate) fn to_raw_packet(self, id: u8) -> RawPacket {
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
            Packet::Generic(raw_packet) => raw_packet,
        }
    }
}

/// Determines if a packet has an extended header
///
/// For now, we'll assume that only PutData packets have extended headers,
/// but this logic can be adjusted as we learn more about the protocol.
fn has_extended_header(packet: &RawPacket) -> bool {
    packet.packet_type() == PacketType::PutData
}
