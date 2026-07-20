use bytes::Bytes;
use km003c_lib::uom::si::ratio::percent;
use km003c_lib::uom::si::time::microsecond;
use km003c_lib::{Packet, PayloadData, RawPacket, Settings};

fn captured_settings() -> Vec<u8> {
    hex::decode(concat!(
        "610150f800000000102741ff00000000",
        "fffffffffffffffffffffffffaffffff",
        "fafffffffafffffffafffffffaffffff",
        "ed4a0f00ed4a0f00ed4a0f00ed4a0f00",
        "ed4a0f00ed4a0f00ed4a0f00ed4a0f00",
        "ed4a0f00ed4a0f005e000000268bb83a",
        "43000000000000000000000000000000",
        "504f5745522d5a000000000000000000",
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "207d05d2"
    ))
    .unwrap()
}

#[test]
fn parses_confirmed_fields_from_captured_settings() {
    let captured = captured_settings();
    let settings = Settings::from_bytes(&captured).unwrap();

    assert_eq!(settings.settings_a_flags(), 0xf850_0161);
    assert_eq!(settings.language_selection(), 1);
    assert!(!settings.is_uncalibrated());
    assert_eq!(settings.brightness().get::<percent>(), 44.0);
    assert_eq!(settings.sample_interval().get::<microsecond>(), 10_000.0);

    assert_eq!(settings.settings_b_flags(), 0x43);
    assert_eq!(settings.screen_orientation(), 3);
    assert_eq!(settings.mtools_device_mode(), 0);
    assert_eq!(settings.selected_main_page(), 1);
    assert_eq!(settings.device_name(), Some("POWER-Z"));
    assert_eq!(settings.to_bytes().as_slice(), captured);
}

#[test]
fn settings_semantic_packet_round_trips_losslessly() {
    let settings = Settings::from_bytes(&captured_settings()).unwrap();
    let raw = Packet::DataResponse {
        payloads: vec![PayloadData::Settings(settings.clone())],
    }
    .to_raw_packet(7)
    .unwrap();
    let reparsed = Packet::try_from(RawPacket::try_from(Bytes::from(raw)).unwrap()).unwrap();

    assert_eq!(reparsed.get_settings(), Some(&settings));
}

#[test]
fn rejects_corrupted_settings_checksums() {
    let mut settings_a_corrupted = captured_settings();
    settings_a_corrupted[0x08] ^= 1;
    assert!(Settings::from_bytes(&settings_a_corrupted).is_err());

    let mut settings_b_corrupted = captured_settings();
    settings_b_corrupted[0x70] ^= 1;
    assert!(Settings::from_bytes(&settings_b_corrupted).is_err());
}
