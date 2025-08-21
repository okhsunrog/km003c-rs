# KM003C PCAP Analysis

This file documents observations from parsing `pd_capture_new.9.pcapng` using `tshark`.

## Observed Frames
- Bulk transfers (transfer_type `0x03`) carry the main protocol data on endpoints `0x01` (H->D) and `0x81` (D->H).
- Host repeatedly sends `GetData` commands with attribute `AdcQueue` (`0x02`). Example hex frame:
  - `0cd00200` (frame 7) → `packet_type=0x0C`, id `0xD0`.
- Device responds with `PutData` packets containing 44 byte ADC payloads. These packets start with bytes such as `41d08202…`.

## Extended Header
For `PutData` responses the first payload dword decodes as:
- `attribute = 0x0001` (`Adc`)
- `next = 0`
- `chunk = 0`
- `size = 44`

This matches the size of the embedded `AdcDataRaw` structure.
Notably the `extend` flag inside the packet header is **zero**, yet the extended header is always present. Parsing code should not rely on that flag.

## Unknown Interrupt Packets
Several interrupt transfers (`transfer_type 0x01`) on endpoint `0x81` contain 8 bytes of data such as `0800000000000000` or `0900000000000000`. Their purpose is currently unknown.
