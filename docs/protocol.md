# POWER-Z KM003C Protocol Description

This document describes the reverse-engineered protocol for the ChargerLAB POWER-Z KM003C USB-C power analyzer. The protocol was analyzed using **Wireshark with usbmon** for USB traffic capture and **Ghidra** for firmware analysis.

## USB Device Identification

- **Vendor ID**: `0x5FC9`
- **Product ID**: `0x0063`
- **Interface**: USB HID with bulk transfer endpoints
- **Endpoints**:
  - **OUT**: `0x01` (host to device)
  - **IN**: `0x81` (device to host)

## Packet Structure

The KM003C uses a custom binary protocol with two main packet types:

### Control Packets
Used for commands and simple responses.

```rust
struct CtrlHeader {
    packet_type: u8,    // Command type
    extend: bool,       // Extended packet flag
    id: u8,            // Transaction ID
    attribute: u16,    // Command attribute
}
```

### Data Packets
Used for data transfer with extended headers for large payloads.

```rust
struct DataHeader {
    packet_type: u8,    // Data type
    extend: bool,       // Extended packet flag
    id: u8,            // Transaction ID
    obj_count_words: u8, // Object count
}

struct ExtendedHeader {
    attribute: u16,     // Data attribute
    next: bool,         // More data flag
    chunk: u8,          // Chunk number
    size: u16,          // Payload size
}
```

`ExtendedHeader` has only been observed on `PutData` responses. Forcing this layout on control packets yields size fields that do
not match their payloads, indicating other packet types do not use this header.

## Packet Types

### Control Commands

| Type | Attribute | Description |
|------|-----------|-------------|
| `GetData` | `Adc` | Request ADC data |
| `GetData` | `PdPacket` | Request PD data |

### Data Responses

| Type | Attribute | Description |
|------|-----------|-------------|
| `PutData` | `Adc` | ADC measurement data |
| `PutData` | `PdPacket` | PD message data |

## ADC Data Format

ADC data is transmitted as a 32-byte structure:

```rust
#[repr(C)]
struct AdcDataRaw {
    vbus_uv: i32,              // VBUS voltage in microvolts
    ibus_ua: i32,              // IBUS current in microamps
    vbus_avg_uv: i32,          // Average VBUS voltage
    ibus_avg_ua: i32,          // Average IBUS current
    vbus_ori_avg_raw: i32,     // Uncalibrated VBUS average
    ibus_ori_avg_raw: i32,     // Uncalibrated IBUS average
    temp_raw: i16,             // Temperature (Celsius * 100)
    vcc1_tenth_mv: u16,        // CC1 voltage (0.1mV)
    vcc2_raw: u16,             // CC2 voltage (0.1mV)
    vdp_mv: u16,               // D+ voltage (0.1mV)
    vdm_mv: u16,               // D- voltage (0.1mV)
    internal_vdd_raw: u16,     // Internal VDD (0.1mV)
    rate_raw: u8,              // Sample rate index
    reserved: u8,              // Reserved/padding
    vcc2_avg_raw: u16,         // Average CC2 voltage
    vdp_avg_mv: u16,           // Average D+ voltage
    vdm_avg_mv: u16,           // Average D- voltage
}
```

### Sample Rates

| Index | Rate | Description |
|-------|------|-------------|
| 0 | 1 SPS | 1 sample per second |
| 1 | 10 SPS | 10 samples per second |
| 2 | 50 SPS | 50 samples per second |
| 3 | 1000 SPS | 1k samples per second |
| 4 | 10000 SPS | 10k samples per second |

### Temperature Conversion

Temperature uses the INA228/9 formula:
```
LSB = 7.8125 m°C = 1000/128
Temperature = ((high_byte * 2000 + low_byte * 1000/128) / 1000)
```

## PD Data Format

PD data contains an "inner event stream" with three packet types concatenated together:

### Connection Events (6 bytes)
```rust
#[repr(C, packed)]
struct ConnectionEvent {
    type_id: u8,              // Always 0x45
    timestamp_bytes: [u8; 3], // 24-bit little-endian timestamp
    _reserved: u8,
    event_data: u8,           // CC pin (bits 7-4) + action (bits 3-0)
}
```

### Status Packets (12 bytes)
```rust
#[repr(C, packed)]
struct StatusPacket {
    type_id: u8,              // Any value except 0x45, 0x80-0x9F
    timestamp_bytes: [u8; 3], // 24-bit little-endian timestamp
    vbus_raw: u16,            // VBUS voltage (raw)
    ibus_raw: u16,            // IBUS current (raw)
    cc1_raw: u16,             // CC1 voltage (raw)
    cc2_raw: u16,             // CC2 voltage (raw)
}
```

### Wrapped PD Messages (Variable length)
```rust
struct WrappedPdMessage {
    is_src_to_snk: bool,      // Message direction
    timestamp: u32,           // 24-bit timestamp
    pd_bytes: Bytes,          // Standard USB PD message
}
```

PD messages are wrapped with a 6-byte header:
- Byte 0: Type ID (0x80-0x9F) + direction bit
- Bytes 1-3: 24-bit timestamp
- Bytes 4-5: Reserved
- Bytes 6+: Standard USB PD message

## Communication Flow

### ADC Data Request
1. Host sends: `GetData` command with `Adc` attribute
2. Device responds: `PutData` with `Adc` attribute containing ADC data

### PD Data Request
1. Host sends: `GetData` command with `PdPacket` attribute
2. Device responds: `PutData` with `PdPacket` attribute containing event stream

## Transaction Management

- Each request gets a unique transaction ID (0-255, wrapping)
- Responses include the same transaction ID for correlation
- Timeout: 2 seconds for all operations

## Error Handling

The device may return error responses or fail to respond within the timeout period. The library implements:
- Automatic retry logic
- Error counting with maximum retry limits
- Graceful degradation on communication failures

## Reverse Engineering Notes

### Tools Used
- **Wireshark + usbmon**: Captured USB traffic between official software and device
- **Ghidra**: Analyzed the original proprietary Qt-based Windows application to understand packet structures and data formats
- **Custom Rust tools**: Built analysis tools to parse captured data

### Key Findings
- Protocol uses simple request-response pattern
- ADC data is transmitted in raw format with calibration applied in software
- PD messages are wrapped but contain standard USB PD protocol
- Timestamps use 24-bit format with millisecond precision
- Device supports multiple sample rates for different use cases

### Limitations
- Some device configuration commands remain unknown
- Firmware update protocol not analyzed
- Advanced measurement modes may isn't reversed yet
- Some proprietary features may use undocumented packet types

### Unknown Packet Types
- Control packet type 0x10 with attribute 0x0001 (length 0) followed by Accept
- Control packet type 0x11 with attribute 0x0000 (length 0) followed by Accept
- GetData with attribute 0x0011 observed

## References

- [USB Power Delivery Specification](https://www.usb.org/document-library/usb-power-delivery)
- [INA228 Datasheet](https://www.ti.com/lit/ds/symlink/ina228.pdf)
- [POWER-Z KM003C Product Page](https://www.power-z.com/products/262)
- [ChargerLAB POWER-Z KM003C/KM002C notes and docs](https://www.chargerlab.com/category/power-z/power-z-km003c-km002c/) 