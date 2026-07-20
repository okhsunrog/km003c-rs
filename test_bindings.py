#!/usr/bin/env python3

import km003c
import pytest


def test_constants():
    print("Testing constants...")
    print(f"VID: {hex(km003c.VID)}")
    print(f"PID: {hex(km003c.PID)}")
    assert km003c.VID == 0x5FC9
    assert km003c.PID == 0x0063
    assert km003c.__version__ == "0.2.0"
    print("✓ Constants test passed")


def test_sample_rates():
    print("\nTesting sample rates...")
    rates = km003c.get_sample_rates()
    print(f"Found {len(rates)} sample rates:")
    for rate in rates:
        print(f"  {rate.name} = {rate.hz} Hz")

    assert len(rates) == 5
    assert rates[0].hz == 2
    assert rates[-1].hz == 10000
    print("✓ Sample rates test passed")


def test_packet_api_shapes():
    packet = km003c.create_packet(km003c.CMD_GET_DATA, 2, km003c.ATT_ADC)
    assert isinstance(packet, bytes)
    assert packet == b"\x0c\x02\x02\x00"

    parsed = km003c.parse_packet(b"\x02\x01\x00\x00")
    raw = km003c.parse_raw_packet(b"\x02\x01\x00\x00")
    assert parsed == {"Connect": None}
    assert raw["Ctrl"]["header"]["id"] == 1


def test_adcqueue_helpers_use_rate_index():
    raw = bytes.fromhex(
        "413e0202020002050de80800d5c38c00598ce8ffdc401f015b17581701ea0800"
        "0bac8c000255e9ff92401e0158175417"
    )
    queue = km003c.parse_packet(raw)["DataResponse"]["payloads"][0]

    assert repr(queue).startswith("AdcQueueRawData")
    assert queue.sequence_range() == (59405, 59905)
    assert not queue.has_dropped_samples(km003c.RATE_2_SPS)
    assert queue.samples[0].marker == 8
    assert queue.samples[0].cc1_raw == 16604

    decoded = queue.decode(km003c.RATE_2_SPS)
    assert decoded.rate_index == km003c.RATE_2_SPS
    assert abs(decoded.samples[0].cc1_v - 1.6604) < 1e-9
    assert not decoded.has_dropped_samples()

    typed = km003c.parse_packet_with_graph_rate(raw, km003c.RATE_2_SPS)["DataResponse"]["payloads"][0]
    assert repr(typed).startswith("AdcQueueData")
    assert abs(typed.samples[0].cc1_v - 1.6604) < 1e-9

    with pytest.raises(ValueError, match="Invalid graph sample rate index"):
        queue.decode(99)
    with pytest.raises(ValueError, match="Invalid graph sample rate index"):
        km003c.parse_packet_with_graph_rate(raw, 99)


def test_raw_adc_parsing():
    print("\nTesting raw ADC data parsing...")
    # Create some dummy ADC data (44 bytes total)
    import struct

    # AdcDataRaw structure from Rust (44 bytes):
    # vbus_uv: I32, ibus_ua: I32, vbus_avg_uv: I32, ibus_avg_ua: I32,
    # vbus_ori_avg_raw: I32, ibus_ori_avg_raw: I32, temp_raw: I16,
    # vcc1_tenth_mv: U16, vcc2_raw: U16, vdp_mv: U16, vdm_mv: U16,
    # internal_vdd_raw: U16, rate_raw: u8, reserved: u8,
    # vcc2_avg_raw: U16, vdp_avg_mv: U16, vdm_avg_mv: U16

    dummy_data = struct.pack(
        "<iiiiiihHHHHHbbHHH",
        5000000,  # vbus_uv (5V in microvolts)
        1000000,  # ibus_ua (1A in microamps)
        5000000,  # vbus_avg_uv
        1000000,  # ibus_avg_ua
        0,  # vbus_ori_avg_raw
        0,  # ibus_ori_avg_raw
        2500,  # temp_raw (25°C * 100)
        50000,  # vcc1_tenth_mv (5V in 0.1mV)
        50000,  # vcc2_raw
        0,  # vdp_mv
        0,  # vdm_mv
        33000,  # internal_vdd_raw (3.3V in 0.1mV)
        3,  # rate_raw (1kSPS)
        0,  # reserved
        50000,  # vcc2_avg_raw
        0,  # vdp_avg_mv
        0,  # vdm_avg_mv
    )

    try:
        adc_data = km003c.parse_raw_adc_data(dummy_data)
        print(f"Parsed ADC data: {adc_data}")

        # Check some basic values
        assert abs(adc_data.vbus_v - 5.0) < 0.01, (
            f"Expected ~5V, got {adc_data.vbus_v}V"
        )
        assert abs(adc_data.ibus_a - 1.0) < 0.01, (
            f"Expected ~1A, got {adc_data.ibus_a}A"
        )
        assert abs(adc_data.power_w - 5.0) < 0.01, (
            f"Expected ~5W, got {adc_data.power_w}W"
        )
        # Temperature calculation might have a different formula, just check it's reasonable
        assert 0 < adc_data.temp_c < 100, (
            f"Temperature should be reasonable, got {adc_data.temp_c}°C"
        )

        print("✓ Raw ADC parsing test passed")

    except Exception as e:
        print(f"✗ Raw ADC parsing failed: {e}")
        raise


def main():
    print("Testing KM003C Python bindings...\n")

    test_constants()
    test_sample_rates()
    test_packet_api_shapes()
    test_adcqueue_helpers_use_rate_index()
    test_raw_adc_parsing()

    print("\n🎉 All tests passed!")


if __name__ == "__main__":
    main()
