pub struct CtrlHeader {
    packet_type: u8,
    extend: bool,
    id: u8,
    _reserved: bool,
    attribute: u16,
}

pub struct DataHeader {
    packet_type: u8,
    extend: bool,
    id: u8,
    _reserved: u8,
    obj_count_words: u16,
}

pub struct ExtendedHeader {
    attribute: u16,
    next: bool,
    chunk: u8,
    size: u16,
}