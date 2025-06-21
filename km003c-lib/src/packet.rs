use crate::error::KMError;
use bytes::Bytes;
use modular_bitfield::prelude::*;

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

#[derive(Debug, Clone, PartialEq)]
pub enum Packet {
    Ctrl { header: CtrlHeader, payload: Bytes },
    Data { header: DataHeader, payload: Bytes },
}

impl TryFrom<Bytes> for Packet {
    type Error = KMError;

    fn try_from(mut bytes: Bytes) -> Result<Self, Self::Error> {
        let is_ctrl_packet = *bytes
            .get(0)
            .ok_or(KMError::InvalidPacket("Missing first byte".to_string()))?
            < 64;
        let header_bytes: [u8; 4] = bytes
            .split_to(4)
            .as_ref()
            .try_into()
            .map_err(|_| KMError::InvalidPacket("Invalid header length".to_string()))?;
        let payload = bytes;
        if is_ctrl_packet {
            let header = CtrlHeader::from_bytes(header_bytes);
            Ok(Packet::Ctrl { header, payload })
        } else {
            let header = DataHeader::from_bytes(header_bytes);
            Ok(Packet::Data { header, payload })
        }
    }
}
