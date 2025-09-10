use crate::error::KMError;
use bytes::Bytes;
use modular_bitfield::prelude::*;
use num_enum::{FromPrimitive, IntoPrimitive};

#[bitfield(bytes = 4)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CtrlHeader {
    pub packet_type: B7,
    pub extend: bool,
    pub id: u8,
    #[skip]
    unused: bool,
    pub attribute: B15,
}

#[bitfield(bytes = 4)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DataHeader {
    pub packet_type: B7,
    pub extend: bool,
    pub id: u8,
    #[skip]
    unused: B6,
    pub obj_count_words: B10,
}

#[bitfield(bytes = 4)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ExtendedHeader {
    pub attribute: B15,
    pub next: bool,
    pub chunk: B6,
    pub size: B10,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoPrimitive, FromPrimitive)]
#[repr(u8)]
pub enum PacketType {
    // 0 is reserved
    // less than 0x40 is ctrl type
    Sync = 0x01,
    Connect = 0x02,
    Disconnect = 0x03,
    Reset = 0x04,
    Accept = 0x05,
    Rejected = 0x06,
    Finished = 0x07,
    JumpAprom = 0x08,
    JumpDfu = 0x09,
    GetStatus = 0x0A,
    Error = 0x0B,
    GetData = 0x0C,
    GetFile = 0x0D,

    // >= 0x40 is data type
    Head = 64,
    PutData = 65,
    Unknown68 = 68,
    Unknown76 = 76,
    Unknown117 = 117,

    #[num_enum(catch_all)]
    Unknown(u8),
}

impl PacketType {
    pub fn is_ctrl_type(&self) -> bool {
        let value: u8 = (*self).into();
        value < 0x40
    }
}

/// Attribute values used in command headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoPrimitive, FromPrimitive)]
#[repr(u16)]
pub enum Attribute {
    None = 0,
    Adc = 0x1,
    AdcQueue = 0x2,
    AdcQueue10k = 0x4,
    Settings = 0x8,
    PdPacket = 0x10,
    PdStatus = 0x20,
    QcPacket = 0x40,

    #[num_enum(catch_all)]
    Unknown(u16),
}

#[derive(Debug, Clone, PartialEq)]
pub enum RawPacket {
    Ctrl { header: CtrlHeader, payload: Bytes },
    SimpleData { header: DataHeader, payload: Bytes },
    ExtendedData { header: DataHeader, ext: ExtendedHeader, payload: Bytes },
}

impl RawPacket {
    pub fn payload(&self) -> Bytes {
        match self {
            RawPacket::Ctrl { payload, .. } => payload.clone(),
            RawPacket::SimpleData { payload, .. } => payload.clone(),
            RawPacket::ExtendedData { payload, .. } => payload.clone(),
        }
    }

    pub fn is_extended(&self) -> bool {
        match self {
            RawPacket::Ctrl { header, .. } => header.extend(),
            RawPacket::SimpleData { header, .. } => header.extend(),
            RawPacket::ExtendedData { header, .. } => header.extend(),
        }
    }

    pub fn id(&self) -> u8 {
        match self {
            RawPacket::Ctrl { header, .. } => header.id(),
            RawPacket::SimpleData { header, .. } => header.id(),
            RawPacket::ExtendedData { header, .. } => header.id(),
        }
    }

    pub fn packet_type(&self) -> PacketType {
        match self {
            RawPacket::Ctrl { header, .. } => PacketType::from_primitive(header.packet_type()),
            RawPacket::SimpleData { header, .. } => PacketType::from_primitive(header.packet_type()),
            RawPacket::ExtendedData { header, .. } => PacketType::from_primitive(header.packet_type()),
        }
    }

    /// Get the extended header if present, without modifying the packet
    pub fn get_extended_header(&self) -> Option<ExtendedHeader> {
        match self {
            RawPacket::ExtendedData { ext, .. } => Some(*ext),
            _ => None,
        }
    }

    /// Get payload data, skipping extended header if present
    pub fn get_payload_data(&self) -> Bytes {
        match self {
            RawPacket::ExtendedData { payload, .. } => payload.clone(),
            _ => self.payload(),
        }
    }

    /// Get the attribute for this packet
    pub fn get_attribute(&self) -> Option<Attribute> {
        match self {
            RawPacket::Ctrl { header, .. } => Some(Attribute::from_primitive(header.attribute())),
            RawPacket::SimpleData { .. } => None,
            RawPacket::ExtendedData { ext, .. } => Some(Attribute::from_primitive(ext.attribute())),
        }
    }
}

impl TryFrom<Bytes> for RawPacket {
    type Error = KMError;

    fn try_from(mut bytes: Bytes) -> Result<Self, Self::Error> {
        // Check minimum length first to prevent panic in split_to(4)
        if bytes.len() < 4 {
            return Err(KMError::InvalidPacket("Packet too short for header".to_string()));
        }

        // the first byte contains packet type (7 bits) + extend bit
        let first_byte = bytes[0]; // Safe now that we know len >= 4
        // Extract only the packet type (lower 7 bits), ignoring the extend bit
        let package_type_byte = first_byte & 0x7F;
        let is_ctrl_packet = PacketType::from_primitive(package_type_byte).is_ctrl_type();

        let header_bytes: [u8; 4] = bytes
            .split_to(4) // Safe now - we know there are at least 4 bytes
            .as_ref()
            .try_into()
            .unwrap(); // Safe to unwrap since we know the slice is exactly 4 bytes
        let payload = bytes;
        if is_ctrl_packet {
            let header = CtrlHeader::from_bytes(header_bytes);
            Ok(RawPacket::Ctrl { header, payload })
        } else {
            let header = DataHeader::from_bytes(header_bytes);
            let packet_type = PacketType::from_primitive(header.packet_type());
            
            // Only PutData packets have extended headers
            if packet_type == PacketType::PutData && payload.len() >= 4 {
                // Parse extended header from first 4 bytes of payload
                let ext_header_bytes: [u8; 4] = payload.as_ref()[..4].try_into()
                    .map_err(|_| KMError::InvalidPacket("Failed to extract extended header bytes".to_string()))?;
                let ext = ExtendedHeader::from_bytes(ext_header_bytes);
                let actual_payload = payload.slice(4..);
                
                Ok(RawPacket::ExtendedData { header, ext, payload: actual_payload })
            } else {
                Ok(RawPacket::SimpleData { header, payload })
            }
        }
    }
}

impl From<RawPacket> for Bytes {
    fn from(packet: RawPacket) -> Self {
        let (header_bytes, payload) = match packet {
            RawPacket::Ctrl { header, payload } => (header.into_bytes(), payload),
            RawPacket::SimpleData { header, payload } => (header.into_bytes(), payload),
            RawPacket::ExtendedData { header, ext, payload } => {
                // For ExtendedData, we need to reconstruct the full payload with extended header
                let mut full_payload = Vec::with_capacity(4 + payload.len());
                full_payload.extend_from_slice(&ext.into_bytes());
                full_payload.extend_from_slice(payload.as_ref());
                (header.into_bytes(), Bytes::from(full_payload))
            }
        };

        // Create the full message by combining header and payload
        let mut message = Vec::with_capacity(4 + payload.len());
        message.extend_from_slice(&header_bytes);
        message.extend_from_slice(payload.as_ref());

        Bytes::from(message)
    }
}
