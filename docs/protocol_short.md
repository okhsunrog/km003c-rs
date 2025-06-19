# KM003C/002C USB Protocol: A Developer's Guide

This document provides a comprehensive guide to the USB communication protocol for the ChargerLAB POWER-Z KM003C and KM002C devices. The information is verified through Ghidra reverse engineering of the official `Mtools.exe` application, USB traffic captures, and community documentation.

## 1. Transport Layer & Interfaces

The device uses a standard USB connection and exposes multiple interfaces. The official application is designed to be robust, automatically selecting the best available interface.

*   **USB Vendor ID (VID):** `0x5FC9` (ChargerLAB)
*   **USB Product ID (PID):** `0x0063` (KM003C)

### 1.1. Multi-Interface Architecture

The device exposes at least four interfaces. A library should ideally attempt to use them in the following order of preference:

| Interface | Type              | Endpoints        | Transfer      | Notes                                                              |
| :-------- | :---------------- | :--------------- | :------------ | :----------------------------------------------------------------- |
| **0**     | **Vendor-Specific** | `0x01` / `0x81`  | **Bulk**      | **Primary high-speed interface.** Requires WinUSB or libusb drivers. |
| **1/2**   | **CDC**           | `0x83`, `0x02`/`0x82` | Int/Bulk      | Virtual Serial Port (VSP).                                         |
| **3**     | **HID**           | `0x05` / `0x85`  | **Interrupt** | **Driver-free fallback.** Works on all OSes but has a 64-byte packet limit. |

**Key Takeaway:** The same command protocol works across all interfaces. The official application transparently switches between `libusb_bulk_transfer` and `libusb_interrupt_transfer` depending on the active interface, providing excellent fallback compatibility.

## 2. Core Protocol Concepts

The protocol is stateful, meaning the order of commands is critical. It operates on a request-response model.

*   **Endianness:** All multi-byte integer values are **little-endian**.
*   **Command ID:** The host maintains a global, 8-bit, auto-incrementing transaction ID. This ID is sent in every command and echoed by the device in its response, allowing the host to match requests with responses.

### 2.1. Command Header Structure

All communication is built upon a fundamental **4-byte command header**. Its structure, confirmed by Ghidra analysis of `build_command_header`, is as follows:

**32-bit Little-Endian Word Layout:**
```
  Bit 31                                 16 15           8 7             0
┌─────┬───────────────────────────────────┬──────────────┬─┬──────────────┐
│  0  │         Attribute (15 bits)       │  ID (8 bits) │0│ Type (7 bits)│
└─────┴───────────────────────────────────┴──────────────┴─┴──────────────┘
```

**Byte-Level Representation (Little-Endian):**

| Byte   | Content               | Description                                |
| :----- | :-------------------- | :----------------------------------------- |
| **0**  | `Type` (7 bits)       | The main command code. Bit 7 is `0`.       |
| **1**  | `ID` (8 bits)         | The transaction ID (0-255).                |
| **2**  | `Attribute` (Low 8)   | The lower 8 bits of the attribute.         |
| **3**  | `Attribute` (High 7)  | The upper 7 bits of the attribute. Bit 7 (`Bit 31` overall) is `0`. |

## 3. Command and Attribute Reference

### 3.1. Command Type Table (`Type`)

| Value  | Name                            | Description                                        |
| :----- | :------------------------------ | :------------------------------------------------- |
| `0x02` | `CMD_CONNECT`                   | Initial handshake to connect to the device.        |
| `0x03` | `CMD_DISCONNECT`                | Cleanly disconnects the session.                   |
| `0x05` | `CMD_ACCEPT`                    | Generic positive acknowledgment from the device.   |
| `0x08` | `CMD_JUMP_APROM`                | Command to jump from bootloader to main application. |
| `0x09` | `CMD_JUMP_DFU`                  | Command to jump from main application to bootloader. |
| `0x0C` | `CMD_GET_DATA`                  | Generic command to request data from the device.   |
| `0x0E` | `CMD_GET_FILE` / `StartStream`  | Starts a continuous data stream (e.g., for logging). |
| `0x0F` | `CMD_STOP_STREAM`               | Stops any active data stream.                      |
| `0x10` | `CMD_SET_CONFIG`                | Sets a configuration parameter using a payload.    |
| `0x11` | `CMD_RESET_CONFIG`              | Resets a configuration (e.g., disables PD sniffer). |
| `0x40` | `CMD_GET_DEVICE_INFO`           | Requests the device information block.             |
| `0x41` | `StatusA`                       | A common response type from the device for data packets. |
| `0x43` | `CMD_SERIAL`                    | Encapsulates a text-based command.                 |
| `0x44` | `CMD_AUTHENTICATE`              | Simple, non-payload authentication step.           |
| `0x48` | `CMD_DATA_WITH_PAYLOAD`         | Base type for commands carrying an 8-byte extended header and data payload. |
| `0x4C` | `CMD_AUTHENTICATE_WITH_PAYLOAD` | Advanced authentication with an encrypted payload. |

### 3.2. Attribute Type Table (`Attribute`)

| Value    | Name                  | Description                                            |
| :------- | :-------------------- | :----------------------------------------------------- |
| `0x0001` | `ATT_ADC`             | Request a single ADC/sensor reading.                   |
| `0x0002` | `ATT_ADC_QUEUE`       | Request a continuous stream of ADC readings.           |
| `0x0008` | `ATT_SETTINGS`        | Attribute for configuration data (e.g., sample rate).  |
| `0x0010` | `ATT_PD_PACKET`       | Request captured Power Delivery protocol packets.      |
| `0x0020` | `ATT_PD_STATUS`       | Request Power Delivery status data (VBUS/IBUS).        |
| `0x0040` | `ATT_QC_PACKET`       | Request captured Qualcomm Quick Charge packets.        |
| `0x0080` | `ATT_TIMESTAMP`       | Attribute for timestamp/status data.                   |
| `0x0180` | `ATT_SERIAL`          | Attribute used with `CMD_SERIAL`.                      |
| `0x0200` | `ATT_AUTH`            | Attribute for authentication and mode switching.       |
| `0x1000` | `ATT_DEVICE_INFO`     | Attribute for device info block (used with `CMD_GET_DATA`). |

## 4. Key Protocol Mechanisms & Command Flows

### 4.1. Initial Connection Sequence

A new connection must follow this sequence to bring the device into an operational state.

1.  **Connect:** Host sends `CMD_CONNECT (0x02)` with `attribute=0`. The device responds with `CMD_ACCEPT (0x05)`.
2.  **Authenticate:** Host performs the multi-step challenge-response authentication. (See Section 4.2).
3.  **Get Device Info:** Host sends `CMD_GET_DATA (0x0C)` with `ATT_DEVICE_INFO (0x1000)` to retrieve the device's capabilities and firmware version. (See Section 5.2).
4.  **Idle State:** The device is now ready. The host can poll for live data or configure it for other tasks.

### 4.2. Authentication Protocol (Challenge-Response)

This is a critical and complex part of the protocol, required for full functionality.

*   **Command:** `CMD_AUTHENTICATE_WITH_PAYLOAD (0x4C)`
*   **Attribute:** `ATT_AUTH (0x0200)`
*   **Process Flow (per step):**
    1.  **Host Challenge:** The host constructs a 32-byte plaintext payload containing an 8-byte timestamp and an 8-byte random nonce.
    2.  **Host Encryption:** This payload is encrypted using AES-128 with a hardcoded key. The key is used **unmodified** for encryption.
    3.  **Transmission:** The host sends the 4-byte header + 32-byte ciphertext.
    4.  **Device Response:** The device replies with an encrypted payload.
    5.  **Host Decryption:** The host decrypts the response using a **modified** version of the same AES key.
    6.  **Verification:** The host confirms the decrypted payload contains the original timestamp and nonce.

*   **AES Key Management:**
    *   Authentication uses a 16-byte key hardcoded in the application (`Key Index 3`).
    *   **Value (Hex):** `46613062347441323566345230333861`
    *   **Value (ASCII):** `"Fa0b4tA25f4R038a"`
    *   **CRITICAL:** For **decryption**, the host modifies the key by overwriting its second byte (index 1) with `0x58` (ASCII `'X'`).

### 4.3. Text Command Encapsulation (Serial Protocol)

The human-readable commands from the official PDF (e.g., `pdm open`, `qc 9V`) are encapsulated in a binary packet before being sent.

*   **Command:** `CMD_SERIAL (0x43)`
*   **Attribute:** `ATT_SERIAL (0x0180)`
*   **Full Packet Structure:**
    1.  **4-byte Header:** `43 <id> 80 01`
    2.  **8-byte Fixed Payload Header:** `00 0C 00 03 3C 00 00 00`
    3.  **Variable Data Payload (ASCII string):** `"<command_string> {UUID} {timestamp} \0LYS"`

### 4.4. Data Streaming (ADC/Sensor Data)

To record high-speed data for charting:

1.  **Set Sample Rate:** Send `CMD_SET_CONFIG (0x10)` with `ATT_SETTINGS (0x0008)`.
    *   **Payload:** A 4-byte little-endian integer representing the sample rate index:
        *   `0`: 1 SPS
        *   `1`: 10 SPS
        *   `2`: 50 SPS
        *   `3`: 1 kSPS
        *   `4`: 10 kSPS
2.  **Start Stream:** Send `CMD_GET_FILE (0x0E)` (repurposed as "start stream"), likely with `attribute=0`. The device will begin sending a continuous stream of ADC data packets.
3.  **Stop Stream:** Send `CMD_STOP_STREAM (0x0F)`.

### 4.5. PD Sniffer (Analyzer) Mode

1.  **Enter Mode:** Send `CMD_SET_CONFIG (0x10)` with `ATT_AUTH (0x0200)`.
2.  **Poll for Data:** In a loop, alternate requests using `CMD_GET_DATA (0x0C)`:
    *   For VBUS/IBUS: use `ATT_PD_STATUS (0x0020)`.
    *   For PD packets: use `ATT_PD_PACKET (0x0010)`.
3.  **Exit Mode:** Send `CMD_RESET_CONFIG (0x11)`.

## 5. Data Packet Structures

### 5.1. ADC Sensor Data Packet (52 bytes)

This is the standard response for sensor data requests. All multi-byte values are little-endian.

| Offset (bytes) | Length | Type       | Description         | Unit / Scale |
| :------------- | :----- | :--------- | :------------------ | :----------- |
| 0-7            | 8      | Header     | Response Headers    | -            |
| 8              | 4      | `int32_t`  | VBUS Voltage        | µV           |
| 12             | 4      | `int32_t`  | IBUS Current        | µA           |
| 16             | 4      | `int32_t`  | VBUS Average        | µV           |
| 20             | 4      | `int32_t`  | IBUS Average        | µA           |
| 24             | 4      | `int32_t`  | VBUS Original Avg   | µV           |
| 28             | 4      | `int32_t`  | IBUS Original Avg   | µA           |
| 32             | 2      | `int16_t`  | Raw Temperature     | -            |
| 34             | 2      | `uint16_t` | VCC1 Voltage        | 0.1 mV       |
| 36             | 2      | `uint16_t` | VCC2 Voltage        | 0.1 mV       |
| 38             | 2      | `uint16_t` | D+ Voltage          | 0.1 mV       |
| 40             | 2      | `uint16_t` | D- Voltage          | 0.1 mV       |
| 42             | 2      | `uint16_t` | Internal VDD        | 0.1 mV       |
| 44             | 1      | `uint8_t`  | Sample Rate Index   | `0..4`         |
| 45             | 1      | `uint8_t`  | Unknown/Padding     | -            |
| 46             | 2      | `uint16_t` | VCC2 Average        | 0.1 mV       |
| 48             | 2      | `uint16_t` | D+ Average          | 0.1 mV       |
| 50             | 2      | `uint16_t` | D- Average          | 0.1 mV       |

### 5.2. Device Information Block (~281 bytes)

This large block is returned in response to `CMD_GET_DATA` with `ATT_DEVICE_INFO`. It contains crucial metadata.

**Key Fields (Offsets are from start of payload, after headers):**

| Offset (bytes) | Length | Description              |
| :------------- | :----- | :----------------------- |
| 0              | 4      | **Firmware version**     |
| 8              | 4      | **Device capabilities flags** |
| 16-111         | 96     | Calibration Data Blocks  |
| 128            | 64     | **Device Name String ("POWER-Z")** followed by null padding |
| ~277           | 4      | Checksum/CRC             |