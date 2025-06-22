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

    // >= 0x40 is ctrl type
    Head = 64,
    PutData = 65,

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
    Data { header: DataHeader, payload: Bytes },
}

impl RawPacket {
    pub fn payload(&self) -> Bytes {
        match self {
            RawPacket::Ctrl { payload, .. } => payload.clone(),
            RawPacket::Data { payload, .. } => payload.clone(),
        }
    }

    pub fn is_extended(&self) -> bool {
        match self {
            RawPacket::Ctrl { header, .. } => header.extend(),
            RawPacket::Data { header, .. } => header.extend(),
        }
    }

    pub fn id(&self) -> u8 {
        match self {
            RawPacket::Ctrl { header, .. } => header.id(),
            RawPacket::Data { header, .. } => header.id(),
        }
    }

    pub fn packet_type(&self) -> PacketType {
        match self {
            RawPacket::Ctrl { header, .. } => PacketType::from_primitive(header.packet_type()),
            RawPacket::Data { header, .. } => PacketType::from_primitive(header.packet_type()),
        }
    }

    pub fn get_ext_header(&mut self) -> Result<ExtendedHeader, KMError> {
        if self.payload().len() < 4 {
            return Err(KMError::InvalidLength);
        }
        let ext_header_bytes = match self {
            RawPacket::Ctrl { payload, .. } => payload.split_to(4),
            RawPacket::Data { payload, .. } => payload.split_to(4),
        };
        let ext_header_bytes: [u8; 4] = ext_header_bytes.as_ref().try_into()?;
        Ok(ExtendedHeader::from_bytes(ext_header_bytes))
    }
}

impl TryFrom<Bytes> for RawPacket {
    type Error = KMError;

    fn try_from(mut bytes: Bytes) -> Result<Self, Self::Error> {
        // the first byte is always package type
        let package_type_byte = *bytes
            .get(0)
            .ok_or(KMError::InvalidPacket("Missing first byte".to_string()))?;
        let is_ctrl_packet = PacketType::from_primitive(package_type_byte).is_ctrl_type();

        let header_bytes: [u8; 4] = bytes
            .split_to(4)
            .as_ref()
            .try_into()
            .map_err(|_| KMError::InvalidPacket("Invalid header length".to_string()))?;
        let payload = bytes;
        if is_ctrl_packet {
            let header = CtrlHeader::from_bytes(header_bytes);
            Ok(RawPacket::Ctrl { header, payload })
        } else {
            let header = DataHeader::from_bytes(header_bytes);
            Ok(RawPacket::Data { header, payload })
        }
    }
}
