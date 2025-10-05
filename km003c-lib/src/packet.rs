#![allow(unused_parens)]

use crate::constants::*;
use crate::error::KMError;
use bytes::Bytes;
use modular_bitfield::prelude::*;
use num_enum::{FromPrimitive, IntoPrimitive};

#[bitfield(bytes = 4)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CtrlHeader {
    pub packet_type: B7,
    /// Reserved flag bit in the first byte. Vendor specific/unknown.
    /// IMPORTANT: This is NOT an indicator that an "extended header" is present.
    /// As per protocol research, PutData (0x41) packets always include a 4-byte
    /// extended header regardless of this bit.
    pub reserved_flag: bool,
    pub id: u8,
    #[skip]
    unused: bool,
    pub attribute: B15,
}

#[bitfield(bytes = 4)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DataHeader {
    pub packet_type: B7,
    /// Reserved flag bit in the first byte. Vendor specific/unknown.
    /// IMPORTANT: This is NOT an indicator that an "extended header" is present.
    /// See CtrlHeader::reserved_flag docs.
    pub reserved_flag: bool,
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

/// KM003C protocol packet types.
///
/// Values < 0x40 are control packet types, >= 0x40 are data packet types.
/// Unknown types have been discovered through protocol analysis but their
/// purpose has not yet been reverse engineered.
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
    StartGraph = 0x0E, // Start AdcQueue streaming with rate selector
    StopGraph = 0x0F,  // Stop AdcQueue streaming

    // Unknown control types discovered in protocol analysis
    Unknown26 = 26,
    Unknown44 = 44,
    Unknown58 = 58,

    // >= 0x40 is data type
    Head = 64,
    PutData = 65,
    // Unknown data types discovered in protocol analysis
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

/// Attribute values used in command headers and extended headers.
///
/// These values specify the type of data or command being sent.
/// Unknown attributes have been discovered through protocol analysis
/// but their purpose has not yet been reverse engineered.
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

    // Unknown attributes discovered in protocol analysis
    // TODO: Reverse engineer the purpose of these attributes
    Unknown512 = 512,     // 0x200 - found with PutData packets
    Unknown1609 = 1609,   // 0x649 - found with Unknown26 packets
    Unknown11046 = 11046, // 0x2B26 - found with Unknown44 packets
    Unknown26817 = 26817, // 0x68C1 - found with Unknown58 packets

    #[num_enum(catch_all)]
    Unknown(u16),
}

// Python support for Attribute
#[cfg(feature = "python")]
impl<'py> pyo3::IntoPyObject<'py> for Attribute {
    type Target = pyo3::PyAny;
    type Output = pyo3::Bound<'py, Self::Target>;
    type Error = pyo3::PyErr;

    fn into_pyobject(self, py: pyo3::Python<'py>) -> Result<Self::Output, Self::Error> {
        // Convert to u16 value for Python
        let value: u16 = self.into();
        Ok(value.into_pyobject(py).unwrap().into_any())
    }
}

/// Set of attributes for use in request masks.
/// Can represent single or multiple attributes combined with bitwise OR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttributeSet {
    mask: u16,
}

impl AttributeSet {
    pub const fn empty() -> Self {
        Self { mask: 0 }
    }

    pub const fn from_raw(mask: u16) -> Self {
        Self { mask }
    }

    pub fn single(attr: Attribute) -> Self {
        Self { mask: attr.into() }
    }

    pub fn from_attributes<I>(attrs: I) -> Self
    where
        I: IntoIterator<Item = Attribute>,
    {
        Self {
            mask: attrs
                .into_iter()
                .map(|a| {
                    let val: u16 = a.into();
                    val
                })
                .fold(0, |acc, x| acc | x),
        }
    }

    pub fn with(mut self, attr: Attribute) -> Self {
        let val: u16 = attr.into();
        self.mask |= val;
        self
    }

    pub fn contains(&self, attr: Attribute) -> bool {
        let val: u16 = attr.into();
        self.mask & val != 0
    }

    /// Check if any of the given attributes are present
    pub fn contains_any<I>(&self, attrs: I) -> bool
    where
        I: IntoIterator<Item = Attribute>,
    {
        attrs.into_iter().any(|a| self.contains(a))
    }

    /// Check if all of the given attributes are present
    pub fn contains_all<I>(&self, attrs: I) -> bool
    where
        I: IntoIterator<Item = Attribute>,
    {
        attrs.into_iter().all(|a| self.contains(a))
    }

    /// Remove an attribute from the set
    pub fn without(mut self, attr: Attribute) -> Self {
        let val: u16 = attr.into();
        self.mask &= !val;
        self
    }

    /// Iterate over all attributes in the set
    pub fn iter(&self) -> impl Iterator<Item = Attribute> + '_ {
        (0..16).filter_map(move |bit| {
            let value = 1u16 << bit;
            if self.mask & value != 0 {
                Some(Attribute::from_primitive(value))
            } else {
                None
            }
        })
    }

    pub fn to_vec(&self) -> Vec<Attribute> {
        self.iter().collect()
    }

    pub const fn raw(&self) -> u16 {
        self.mask
    }

    pub fn is_empty(&self) -> bool {
        self.mask == 0
    }

    pub fn len(&self) -> usize {
        self.mask.count_ones() as usize
    }
}

impl From<Attribute> for AttributeSet {
    fn from(attr: Attribute) -> Self {
        Self::single(attr)
    }
}

impl FromIterator<Attribute> for AttributeSet {
    fn from_iter<I: IntoIterator<Item = Attribute>>(iter: I) -> Self {
        Self::from_attributes(iter)
    }
}

/// Represents a single logical packet within a PutData response.
/// PutData packets can contain multiple chained logical packets,
/// each with its own extended header and payload.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "python", pyo3::pyclass(get_all, name = "LogicalPacket"))]
pub struct LogicalPacket {
    pub attribute: Attribute,
    pub next: bool,
    pub chunk: u8,
    pub size: u16,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RawPacket {
    Ctrl {
        header: CtrlHeader,
        payload: Vec<u8>,
    },
    SimpleData {
        header: DataHeader,
        payload: Vec<u8>,
    },
    Data {
        header: DataHeader,
        logical_packets: Vec<LogicalPacket>,
    },
}

impl RawPacket {
    pub fn id(&self) -> u8 {
        match self {
            RawPacket::Ctrl { header, .. } => header.id(),
            RawPacket::SimpleData { header, .. } => header.id(),
            RawPacket::Data { header, .. } => header.id(),
        }
    }

    pub fn packet_type(&self) -> PacketType {
        match self {
            RawPacket::Ctrl { header, .. } => PacketType::from_primitive(header.packet_type()),
            RawPacket::SimpleData { header, .. } => PacketType::from_primitive(header.packet_type()),
            RawPacket::Data { header, .. } => PacketType::from_primitive(header.packet_type()),
        }
    }

    /// Get the attribute for control packets
    pub fn get_attribute(&self) -> Option<Attribute> {
        match self {
            RawPacket::Ctrl { header, .. } => Some(Attribute::from_primitive(header.attribute())),
            _ => None,
        }
    }

    /// Get the attribute set for control packets (for GetData requests)
    pub fn get_attribute_set(&self) -> Option<AttributeSet> {
        match self {
            RawPacket::Ctrl { header, .. } => Some(AttributeSet::from_raw(header.attribute())),
            _ => None,
        }
    }

    /// Get logical packets for Data variant
    pub fn logical_packets(&self) -> Option<&[LogicalPacket]> {
        match self {
            RawPacket::Data { logical_packets, .. } => Some(logical_packets),
            _ => None,
        }
    }

    /// Validate that response attributes match the request mask
    ///
    /// Returns Ok(()) if all response attributes were requested in the mask,
    /// or Err if there's a mismatch.
    pub fn validate_correlation(&self, request_mask: u16) -> Result<(), KMError> {
        match self {
            RawPacket::Data { logical_packets, .. } => {
                let request_set = AttributeSet::from_raw(request_mask);

                // Check each logical packet's attribute
                for lp in logical_packets {
                    if !request_set.contains(lp.attribute) {
                        let expected: Vec<u16> = request_set.iter().map(|a| a.into()).collect();
                        let actual: Vec<u16> = logical_packets.iter().map(|lp| lp.attribute.into()).collect();

                        return Err(KMError::AttributeMismatch { expected, actual });
                    }
                }

                Ok(())
            }
            _ => Ok(()), // Non-data packets don't need validation
        }
    }

    /// Check if this is an empty PutData response (no logical packets)
    pub fn is_empty_response(&self) -> bool {
        matches!(self, RawPacket::Data { logical_packets, .. } if logical_packets.is_empty())
    }
}

impl TryFrom<Bytes> for RawPacket {
    type Error = KMError;

    fn try_from(mut bytes: Bytes) -> Result<Self, Self::Error> {
        // Check minimum length first to prevent panic in split_to
        if bytes.len() < MAIN_HEADER_SIZE {
            return Err(KMError::InvalidPacket(format!(
                "Packet too short for header: expected {}, got {}",
                MAIN_HEADER_SIZE,
                bytes.len()
            )));
        }

        // the first byte contains packet type (7 bits) + header flag bit
        let first_byte = bytes[0]; // Safe now that we know len >= 4
        // Extract only the packet type (lower 7 bits), ignoring the header flag bit
        let package_type_byte = first_byte & 0x7F;
        let is_ctrl_packet = PacketType::from_primitive(package_type_byte).is_ctrl_type();

        let header_bytes: [u8; 4] = bytes
            .split_to(4) // Safe now - we know there are at least 4 bytes
            .as_ref()
            .try_into()
            .unwrap(); // Safe to unwrap since we know the slice is exactly 4 bytes
        let mut payload = bytes;

        if is_ctrl_packet {
            let header = CtrlHeader::from_bytes(header_bytes);
            Ok(RawPacket::Ctrl {
                header,
                payload: payload.to_vec(),
            })
        } else {
            let header = DataHeader::from_bytes(header_bytes);
            let packet_type = PacketType::from_primitive(header.packet_type());

            // Only PutData packets have chained logical packets with extended headers
            if packet_type == PacketType::PutData {
                // Check for empty PutData (obj_count_words == 0)
                if header.obj_count_words() == 0 || payload.is_empty() {
                    // Valid empty response - device has no data
                    return Ok(RawPacket::Data {
                        header,
                        logical_packets: vec![],
                    });
                }

                if payload.len() < EXTENDED_HEADER_SIZE {
                    // TODO(okhsunrog): Spec indicates all PutData (0x41) packets
                    //                   must carry a 4-byte extended header. We currently
                    //                   fall back to SimpleData when payload < 4 for
                    //                   robustness against malformed frames.
                    return Ok(RawPacket::SimpleData {
                        header,
                        payload: payload.to_vec(),
                    });
                }

                // Parse chained logical packets
                let mut logical_packets = Vec::new();

                loop {
                    if payload.len() < EXTENDED_HEADER_SIZE {
                        return Err(KMError::InvalidPacket(format!(
                            "Insufficient bytes for extended header: need {}, got {}",
                            EXTENDED_HEADER_SIZE,
                            payload.len()
                        )));
                    }

                    // Parse extended header
                    let ext_header_bytes: [u8; 4] = payload.as_ref()[..4]
                        .try_into()
                        .map_err(|_| KMError::InvalidPacket("Failed to extract extended header bytes".to_string()))?;
                    let ext = ExtendedHeader::from_bytes(ext_header_bytes);

                    let payload_size = ext.size() as usize;
                    let has_next = ext.next();
                    let attribute = Attribute::from_primitive(ext.attribute());

                    // Skip extended header
                    payload = payload.slice(4..);

                    // For AdcQueue, the size field indicates sample size (20 bytes),
                    // but the actual payload contains multiple samples.
                    // Take all remaining payload if this is the last logical packet.
                    let logical_payload = if !has_next && attribute == Attribute::AdcQueue {
                        // Last packet and AdcQueue: take all remaining bytes
                        let all = payload.clone();
                        payload = Bytes::new();
                        all
                    } else {
                        // Normal case: take exactly size bytes
                        if payload.len() < payload_size {
                            return Err(KMError::InvalidPacket(format!(
                                "Insufficient payload bytes: expected {}, got {}",
                                payload_size,
                                payload.len()
                            )));
                        }
                        let chunk = payload.slice(..payload_size);
                        payload = payload.slice(payload_size..);
                        chunk
                    };

                    logical_packets.push(LogicalPacket {
                        attribute,
                        next: has_next,
                        chunk: ext.chunk(),
                        size: ext.size(),
                        payload: logical_payload.to_vec(),
                    });

                    // Check if there are more logical packets
                    if !has_next {
                        break;
                    }
                }

                if logical_packets.is_empty() {
                    return Err(KMError::InvalidPacket(
                        "PutData packet must have at least one logical packet".to_string(),
                    ));
                }

                Ok(RawPacket::Data {
                    header,
                    logical_packets,
                })
            } else {
                Ok(RawPacket::SimpleData {
                    header,
                    payload: payload.to_vec(),
                })
            }
        }
    }
}

// Python support
#[cfg(feature = "python")]
impl<'py> pyo3::IntoPyObject<'py> for RawPacket {
    type Target = pyo3::PyAny;
    type Output = pyo3::Bound<'py, Self::Target>;
    type Error = pyo3::PyErr;

    fn into_pyobject(self, py: pyo3::Python<'py>) -> Result<Self::Output, Self::Error> {
        use pyo3::types::{PyDict, PyDictMethods, PyListMethods};

        let dict = PyDict::new(py);
        match self {
            RawPacket::Ctrl { header, payload } => {
                let inner = PyDict::new(py);
                let header_dict = PyDict::new(py);
                header_dict.set_item("packet_type", header.packet_type())?;
                header_dict.set_item("reserved_flag", header.reserved_flag())?;
                header_dict.set_item("id", header.id())?;
                header_dict.set_item("attribute", header.attribute())?;
                inner.set_item("header", header_dict)?;
                inner.set_item("payload", payload)?;
                dict.set_item("Ctrl", inner)?;
            }
            RawPacket::SimpleData { header, payload } => {
                let inner = PyDict::new(py);
                let header_dict = PyDict::new(py);
                header_dict.set_item("packet_type", header.packet_type())?;
                header_dict.set_item("reserved_flag", header.reserved_flag())?;
                header_dict.set_item("id", header.id())?;
                header_dict.set_item("obj_count_words", header.obj_count_words())?;
                inner.set_item("header", header_dict)?;
                inner.set_item("payload", payload)?;
                dict.set_item("SimpleData", inner)?;
            }
            RawPacket::Data {
                header,
                logical_packets,
            } => {
                let inner = PyDict::new(py);
                let header_dict = PyDict::new(py);
                header_dict.set_item("packet_type", header.packet_type())?;
                header_dict.set_item("reserved_flag", header.reserved_flag())?;
                header_dict.set_item("id", header.id())?;
                header_dict.set_item("obj_count_words", header.obj_count_words())?;
                inner.set_item("header", header_dict)?;
                // Convert LogicalPacket vec -> list of dicts for Python
                let lp_list = pyo3::types::PyList::empty(py);
                for lp in logical_packets {
                    let lp_dict = PyDict::new(py);
                    lp_dict.set_item("attribute", u16::from(lp.attribute))?;
                    lp_dict.set_item("next", lp.next)?;
                    lp_dict.set_item("chunk", lp.chunk)?;
                    lp_dict.set_item("size", lp.size)?;
                    lp_dict.set_item("payload", lp.payload)?;
                    lp_list.append(lp_dict)?;
                }
                inner.set_item("logical_packets", lp_list)?;
                dict.set_item("Data", inner)?;
            }
        }
        Ok(dict.into_any())
    }
}

impl From<RawPacket> for Bytes {
    fn from(packet: RawPacket) -> Self {
        let (header_bytes, payload) = match packet {
            RawPacket::Ctrl { header, payload } => (header.into_bytes(), payload),
            RawPacket::SimpleData { header, payload } => (header.into_bytes(), payload),
            RawPacket::Data {
                header,
                logical_packets,
            } => {
                // Reconstruct chained logical packets
                let mut full_payload = Vec::new();

                for logical_packet in logical_packets {
                    // Build extended header
                    let ext = ExtendedHeader::new()
                        .with_attribute(logical_packet.attribute.into())
                        .with_next(logical_packet.next)
                        .with_chunk(logical_packet.chunk)
                        .with_size(logical_packet.size);

                    full_payload.extend_from_slice(&ext.into_bytes());
                    full_payload.extend_from_slice(&logical_packet.payload);
                }

                (header.into_bytes(), full_payload)
            }
        };

        // Create the full message by combining header and payload
        let mut message = Vec::with_capacity(4 + payload.len());
        message.extend_from_slice(&header_bytes);
        message.extend_from_slice(payload.as_ref());

        Bytes::from(message)
    }
}
