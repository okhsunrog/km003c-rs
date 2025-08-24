# POWER-Z KM003C Protocol Description

This document describes the reverse-engineered protocol for the ChargerLAB POWER-Z KM003C USB-C power analyzer. The protocol was analyzed using **Wireshark with usbmon**, **Ghidra**, and official developer example code (`hiddemo_vs2019_for-KM002C3C.zip`).

## USB Device Identification

-   **Vendor ID**: `0x5FC9`
-   **Product ID**: `0x0063`
-   **Interfaces**: The device exposes multiple USB interfaces, each with different endpoints and performance characteristics.

| Interface | Endpoints (OUT/IN) | bInterfaceClass | Typical Sample Rate |
| :-------- | :----------------- | :-------------- | :------------------ |
| 0         | `0x01` / `0x81`    | Vendor Specific | ~1000 sps           |
| 1         | `0x05` / `0x85`    | HID             | ~500 sps            |
| 3         | `0x03` / `0x83`    | CDC Data        | ~1000 sps           |

## Packet Structure

The protocol uses a custom binary format with two main packet structures, distinguished by the `type` field in the first byte.

### Control Packets (type < 0x40)

Used for commands and simple responses. These consist of a 4-byte header and an optional payload.

```rust
struct CtrlHeader {
    packet_type: u8,    // Command type (7 bits)
    extend: bool,       // Official name for this flag. Used for large data transfers.
    id: u8,             // Transaction ID
    attribute: u16,     // Command attribute (15 bits)
}
```

### Data Packets (type >= 0x40)

Used for all data transfers from the device to the host. These packets have a consistent 8-byte, two-part header followed by a payload.

```rust
struct DataHeader {        // Bytes 0-3
    packet_type: u8,       // Data type (7 bits)
    extend: bool,          // See above
    id: u8,                // Transaction ID
    obj_count_words: u16,  // Object count (10 bits)
}

struct ExtendedHeader {    // Bytes 4-7
    attribute: u16,        // Data attribute (15 bits)
    next: bool,            // Signals a composite payload
    chunk: u8,             // Chunk number
    size: u16,             // Size of the first part of the payload (10 bits)
}
```

The `extend` bit's purpose is for handling very large data transfers, though the exact mechanism is not fully clear from the examples. The `next` bit in the `ExtendedHeader` is critical for parsing, as it indicates that the payload contains more than one type of data.

## Communication Flow

### Standard ADC Data Request

1.  **Host Sends:** `GetData` command (type `0x0C`) with `Attribute::AdcQueue` (value `0x002`).
2.  **Device Responds:** `PutData` packet (type `0x41`) with an `ExtendedHeader` containing `Attribute::Adc` (value `0x001`), `next: false`, and `size: 44`. The payload is a single 44-byte `AdcDataRaw` structure.

### Standard PD Data Request

1.  **Host Sends:** `GetData` command (type `0x0C`) with `Attribute::PdPacket` (value `0x010`).
2.  **Device Responds:** `PutData` packet (type `0x41`) with an `ExtendedHeader` containing `Attribute::PdPacket`, `next: false`, and a `size` matching the length of the event stream payload.

### Combined ADC + PD Data Request

1.  **Host Sends:** `GetData` command (type `0x0C`) with a combined attribute, typically `0x0011` (`Adc | PdPacket`) or `0x0017` (`AdcQueue | AdcQueue10k | PdPacket`).
2.  **Device Responds:** `PutData` packet (type `0x41`) with an `ExtendedHeader` containing:
    *   `attribute`: `Attribute::Adc` (value `0x001`)
    *   `next`: **`true`**
    *   `size`: `44`
    *   The payload is a composite: the first 44 bytes are the `AdcDataRaw` structure, and the remaining bytes are the "inner PD event stream."

## ADC Data Format (`AdcDataRaw`, 44 bytes)

The data structure for ADC readings, as confirmed by Wireshark captures, is 44 bytes long. Note that the official example code and documentation show an older, incomplete 40-byte version.

```rust
#[repr(C)]
struct AdcDataRaw {
    vbus_uv: i32,          // VBUS voltage in microvolts
    ibus_ua: i32,          // IBUS current in microamps (signed)
    vbus_avg_uv: i32,      // Average VBUS voltage
    ibus_avg_ua: i32,      // Average IBUS current
    vbus_ori_avg_raw: i32, // Uncalibrated VBUS average
    ibus_ori_avg_raw: i32, // Uncalibrated IBUS average
    temp_raw: i16,         // Temperature (INA228/9 format)
    vcc1_tenth_mv: u16,    // CC1 voltage (0.1mV)
    vcc2_raw: u16,         // CC2 voltage (0.1mV)
    vdp_mv: u16,           // D+ voltage (0.1mV)
    vdm_mv: u16,           // D- voltage (0.1mV)
    internal_vdd_raw: u16, // Internal VDD (0.1mV)
    rate_raw: u8,          // Sample rate index
    reserved: u8,          // Reserved/padding
    vcc2_avg_raw: u16,     // Average CC2 voltage (0.1mV)
    vdp_avg_mv: u16,       // Average D+ voltage (0.1mV)
    vdm_avg_mv: u16,       // Average D- voltage (0.1mV)
}
```

## PD Inner Event Stream (Revised)

The payload of a `PutData` packet with `PdPacket` (0x10) or `PdStatus` (0x20) attributes is a concatenated stream of inner records. Each record has an 8-byte meta header followed by a variable-length body. This section supersedes earlier 6-byte header descriptions.

### Outer Framing and Combined Payloads

- A `PutData` payload that carries PD/Status begins with a 12-byte ADC snapshot: `u16 VBUS @+4`, `s16 IBUS @+6`, `u16 CC1 @+8`, `u16 CC2 @+10`. After these 12 bytes, the inner event stream begins.
- Records are concatenated until the end of the payload; a meta flag can indicate more chunks at the outer layer (`next` in the extended header).

### Inner Record Meta Header (8 bytes)

Bytes are little-endian where applicable. Offsets shown are relative to the start of each record.

- [0..=3]: `u32` timestamp (ticks)
- [4]: flags/status (UI uses bits here to choose DP/DM label)
- [5]: flags/status (unknown semantics)
- [6]: `u8` body length (number of bytes following the header)
- [7]: flags/status (unknown semantics)

The parsing loop advances by `8 + length` per record.

### Record Body Types

1) Connection Event

- Discriminator: first body byte `0x45`
- Body layout (2 bytes): `0x45, event_data`
- Meaning: `event_data` lower 4 bits = action (1=Attach, 2=Detach, …); upper 4 bits = CC pin (1=CC1, 2=CC2)

2) Status Update

- Discriminator: not `0x45`, not PD prelude (see below), and body length ≥ 8
- Body layout (8 bytes): `u16 VBUS, s16 IBUS, u16 CC1, u16 CC2`

3) PD-Wrapped Record

- Discriminator: PD prelude marker present at the start of the body
- Body layout (indices relative to body start):
  - [0] = `0xAA`
  - [1..=3] = 3-byte header; `[1]` contains direction bit (`& 0x04`); `[2] & 0x07` has SOP info (SOP when zero)
  - [4] = CRC-8 over `[1..=3]` with polynomial `0x29`, init `0x00`
  - [5] = `0xAA`
  - [6..=12] = auxiliary bytes (purpose unknown)
  - [13..] = standard USB-PD message (16-bit header + data objects)

Validation used by the Windows app:

- `body[0] == 0xAA` and `body[5] == 0xAA`
- `(body[2] & 0x07) == 0` (SOP)
- `crc8_0x29(body[1..=3]) == body[4]`

Normalization in the Windows app (for display/storage):

- Decrease meta header `[6]` (length) by 5
- Overwrite the first 7 bytes of the event slice: write relative time (4 bytes), zeros at [4..5], kind `0x05` at [6]
- Drop the first `0x0D` bytes of the body (the PD prelude) before presenting; prepend the 8-byte meta header

In this repository, the parser instead detects the prelude and exposes the PD bytes directly from `[13..]` as `WrappedPdMessage`.

### Attributes and Flow

- `Attribute::PdPacket (0x10)`: PD sniffer data; when enabled, emits PD inner stream records.
- `Attribute::PdStatus (0x20)`: Similar inner stream; firmware logs hex in some paths but the structure matches the above.
- The outer handler uses transaction IDs and the extended-header `next` flag to handle chunked payloads; decryption paths exist for large transfers but aren’t used for PD in observed traces.

### Notes

- Earlier 6-byte inner headers found in Pascal examples appear to be a different or older framing and do not match the Windows app analyzed here.
- Some meta-header flag bits ([4], [5], [7]) influence UI labeling (DP/DM, role/source/cable). Exact bitfields are still being mapped.

## Transaction Management

-   Each request from the host has a unique transaction ID (0-255, wrapping).
-   The device's response mirrors the same ID in its `DataHeader`.
-   A default timeout of 2 seconds is recommended for all operations.

## References

-   [USB Power Delivery Specification](https://www.usb.org/document-library/usb-power-delivery)
-   [ChargerLAB Developer Resources](https://www.chargerlab.com/wp-content/uploads/2019/05/hiddemo_vs2019_for-KM002C3C.zip) (Contains C++ and Pascal examples)
