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

## PD "Inner Event Stream" Format

The payload of a `PutData` packet with the `PdPacket` attribute is not a single PD message but a stream of smaller, concatenated "event" packets. Each event packet begins with its own **6-byte header**.

#### Inner Event Header (6 bytes)

```pascal
// As defined in the Pascal example
TKM003CPacketHeader = packed record
  Size: Byte;             // Length of the following event data. Bit 7 is a flag.
  Time: DWord;            // 32-bit timestamp
  SOP: Byte;              // SOP type (SOP, SOP', etc.)
end;
```
The `Size` field's 8th bit (`(Size & 0x80) != 0`) indicates if the following event is a standard PD message (a "SOP Packet").

### Inner Event Types

1.  **Connection Events (`type_id: 0x45`, 6 bytes):** Signals Attach/Detach.
2.  **Status Packets (12 bytes):** Provides periodic Vbus/Ibus/CC updates.
3.  **Wrapped PD Messages (variable length):** Contains a standard USB-PD message.

These events are parsed from the stream after their 6-byte inner header.

## Transaction Management

-   Each request from the host has a unique transaction ID (0-255, wrapping).
-   The device's response mirrors the same ID in its `DataHeader`.
-   A default timeout of 2 seconds is recommended for all operations.

## References

-   [USB Power Delivery Specification](https://www.usb.org/document-library/usb-power-delivery)
-   [ChargerLAB Developer Resources](https://www.chargerlab.com/wp-content/uploads/2019/05/hiddemo_vs2019_for-KM002C3C.zip) (Contains C++ and Pascal examples)