use crate::error::KMError;
use bytes::Bytes;
use modular_bitfield::prelude::*;

#[bitfield(bytes = 4)]
#[derive(Debug, Clone, Copy)]
pub struct CtrlHeader {
    packet_type: B7,
    extend: bool,
    id: u8,
    #[skip]
    unused: bool,
    attribute: B15,
}

#[bitfield(bytes = 4)]
#[derive(Debug, Clone, Copy)]
pub struct DataHeader {
    packet_type: B7,
    extend: bool,
    id: u8,
    #[skip]
    unused: B6,
    obj_count_words: B10,
}

#[bitfield(bytes = 4)]
#[derive(Debug, Clone, Copy)]
pub struct ExtendedHeader {
    attribute: B15,
    next: bool,
    chunk: B6,
    size: B10,
}

#[derive(Debug, Clone)]
pub enum Packet {
    Ctrl { header: CtrlHeader, payload: Bytes },
    Data { header: DataHeader, payload: Bytes },
}

impl TryFrom<Bytes> for Packet {
    type Error = KMError;

    fn try_from(bytes: Bytes) -> Result<Self, Self::Error> {
        let is_ctrl_packet = *bytes
            .get(0)
            .ok_or(KMError::InvalidPacket("Missing first byte".to_string()))?
            < 64;
        let header_bytes: [u8; 4] = bytes[0..4].try_into()?;
        if is_ctrl_packet {
            let header = CtrlHeader::from_bytes(header_bytes);
            let payload = bytes.slice(4..);
            Ok(Packet::Ctrl { header, payload })
        } else {
            let header = DataHeader::from_bytes(header_bytes);
            let payload = bytes.slice(4..);
            Ok(Packet::Data { header, payload })
        }
    }
}
