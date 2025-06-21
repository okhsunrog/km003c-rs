use modular_bitfield::prelude::*;

#[bitfield(bytes = 4)]
pub struct CtrlHeader {
    packet_type: B7,
    extend: bool,
    id: u8,
    #[skip]
    unused: bool,
    attribute: B15,
}

#[bitfield(bytes = 4)]
pub struct DataHeader {
    packet_type: B7,
    extend: bool,
    id: u8,
    #[skip]
    unused: B6,
    obj_count_words: B10,
}

#[bitfield(bytes = 4)]
pub struct ExtendedHeader {
    attribute: B15,
    next: bool,
    chunk: B6,
    size: B10,
}
