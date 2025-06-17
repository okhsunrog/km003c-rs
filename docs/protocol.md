# Comprehensive Protocol Guide: ChargerLAB POWER-Z KM003C

This document details the USB communication protocol for the ChargerLAB POWER-Z KM003C device. The information has been compiled and verified through analysis of official but incomplete documentation, a Pascal header file, a minimal Linux kernel driver, and extensive, iterative USB traffic capture analysis.

## 1. Core Concepts & Transport Layer

The protocol operates over a standard USB Bulk interface, which is presented to the operating system as a Vendor-Specific (WinUSB/libusb) device.

*   **USB Vendor ID (VID):** `0x5FC9` (ChargerLAB)
*   **USB Product ID (PID):** `0x0063` (KM003C)
*   **Host-to-Device Endpoint (OUT):** `0x01`
*   **Device-to-Host Endpoint (IN):** `0x81`

All communication consists of a **4-byte command header**, optionally followed by a data payload. All multi-byte integer values in the protocol are **little-endian**.

## 2. Command Header Structure

The 4-byte header is the fundamental building block of all communication. Its bitfields are interpreted differently based on the message context, but the primary structure for host-sent commands is as follows:

| Field | Bits | Description |
| :--- | :--- | :--- |
| `type` | 7 | The main command code. See `CommandType` enum. |
| `extend`| 1 | A flag used for multi-packet data transfers. |
| `id` | 8 | A transaction ID (0-255), incremented by the host for each new command. The device echoes this ID in its response to correlate request/response pairs. |
| `rsvd` | 1 | A reserved bit, observed to be `0` in commands. |
| `att` | 15 | The "Attribute" code, specifying the target or sub-function of the command. See `Attribute` enum. |

## 3. Protocol State Machine and Command Sequences

The KM003C is a stateful device. It must be placed into the correct mode before certain commands will work. The official PC application follows a distinct sequence.

### Sequence A: Initial Connection and Handshake

This sequence is required to bring the device online and into a known idle state.

1.  **Host Sends `CMD_CONNECT`:** The host signals its presence.
    *   **Command:** `02 01 00 00` (`type=0x02`, `id=1`, `att=0`)
    *   The device responds with `CMD_ACCEPT` (`05 01 00 00`).

2.  **Host Performs Authentication (Optional but Recommended):**
    *   The host sends a series of packets with `type=0x44` and `att` values from `1` to `5`. Each packet contains a long, likely encrypted payload. This is a challenge-response handshake to unlock advanced features. *This step can likely be skipped for basic ADC reading but is required for PD Analyzer mode.*

3.  **Host Sets Operational Mode:** The host must explicitly tell the device which "personality" to adopt.
    *   **For Data Recorder Mode:** `4c XX 00 02` + [long payload]
        *   This undocumented `type=0x4c` command, using `att=ATT_ADC_QUEUE`, initializes the device for VBUS/IBUS logging.
    *   **For PD Analyzer Mode:** `0c XX 00 04`
        *   This is a repurposed `CMD_GET_DATA` command using the undocumented attribute `att=512`.

4.  **Host Settles to Idle:**
    *   A stop command, typically `0f XX 00 00`, is sent to ensure all prior operations are halted.

5.  **Idle Polling:** In the absence of an active high-speed stream, the host application sends `0c XX 02 00` (`CMD_GET_DATA`, `att=ATT_ADC`) every 200-500ms to receive a single, low-rate `AdcData` packet to update the live dashboard values.

### Sequence B: High-Speed Data Recording / Charting

This sequence details how to configure and stream high-frequency data. It assumes the device is in the idle state.

1.  **Set Sample Rate:** This is a **configuration** step. It tells the device what speed its internal ADC queue should run at. It does **not** start the data flow.
    *   **Command:** `10 XX 10 00` + `[4-byte Rate Payload]`
    *   **Type:** `0x10` (`SetConfig`)
    *   **Attribute:** `0x0008` (`ATT_SETTINGS`)
    *   **Payload:** The sample rate as a 4-byte little-endian integer.
        *   1 SPS: `01 00 00 00`
        *   10 SPS: `0a 00 00 00`
        *   50 SPS: `32 00 00 00`
        *   1000 SPS: `e8 03 00 00`

2.  **Start High-Speed Data Stream:**
    *   **Command:** `0c XX 04 00`
    *   **Type:** `0x0c` (`CMD_GET_DATA`)
    *   **Attribute:** `0x0002` (`ATT_ADC_QUEUE`)
    *   This command initiates the data "firehose". The host must continuously send this command to keep receiving data packets. The application is responsible for plotting this data for a live chart or saving it to a file.

3.  **Stop High-Speed Data Stream:**
    *   **Command:** `0f XX 00 00` (Undocumented `STOP` command).
    *   This halts the stream, and the device returns to an idle state.

### Sequence C: PD Sniffing (PD Analyzer Mode)

This sequence is for capturing and decoding USB Power Delivery protocol messages.

1.  **Switch to PD Analyzer Mode:** (See Sequence A, Step 3)
    *   **Command:** `0c XX 00 04`

2.  **Poll for PD Data:**
    *   The host rapidly alternates polling two different attributes:
        *   To get VBUS/IBUS values: `0c XX 20 00` (`att=ATT_PD_STATUS`)
        *   To get PD protocol packets: `0c XX 10 00` (`att=ATT_PD_PACKET`)

3.  **Start/Stop Logging to File (in PD Mode):**
    *   **Start:** `0e XX 00 00` (Repurposed `CMD_GET_FILE`)
    *   **Stop:** `0f XX 00 00`

---

## 4. Enums and Data Structures

### CommandType (`type`)

| Value | Name | Description |
| :--- | :--- | :--- |
| `0x02` | `CMD_CONNECT` | Initial handshake command. |
| `0x05` | `CMD_ACCEPT` | Standard positive acknowledgement from device. |
| `0x0C` | `CMD_GET_DATA` | Primary command to request data from the device. |
| `0x0E` | `CMD_GET_FILE` | Documented as getting a file, but used to start PD logging. |
| `0x0F` | `(undocumented)` | **STOP_STREAM**. The most common command to halt any data stream. |
| `0x10` | `(undocumented)` | **SET_CONFIG**. Writes a configuration value (e.g., sample rate). |
| `0x44` | `(undocumented)` | **AUTHENTICATE**. Part of the initial security handshake. |
| `0x4C` | `(undocumented)` | **SET_RECORDER_MODE**. Initializes the device for VBUS/IBUS logging. |

### Attribute (`att`)

| Value | Name | Description |
| :--- | :--- | :--- |
| `0x0001` | `ATT_ADC` | Target for low-rate, single-shot sensor data. |
| `0x0002` | `ATT_ADC_QUEUE` | Target for high-rate, continuous sensor data stream. |
| `0x0008` | `ATT_SETTINGS` | Target for the `SET_CONFIG` command to write settings like sample rate. |
| `0x0010` | `ATT_PD_PACKET` | Target for retrieving captured PD protocol packets. |
| `0x0020` | `ATT_PD_STATUS` | Target for retrieving VBUS/IBUS data while in PD mode. |
| `0x0200` | `(undocumented)` | Target for the `CMD_GET_DATA` command to switch into PD Analyzer mode. |

### ADC Sensor Data Packet Structure

This is the 52-byte packet returned by the device in Data Recorder mode. All multi-byte values are little-endian.

| Offset (bytes) | Length (bytes) | Data Type | Description | Unit |
| :--- | :--- | :--- | :--- | :--- |
| 0 | 4 | Header | Response Header | - |
| 4 | 4 | Header | Extended Header | - |
| 8 | 4 | `i32` | VBUS Voltage | uV |
| 12 | 4 | `i32` | IBUS Current | uA |
| 16 | 4 | `i32` | VBUS Average | uV |
| 20 | 4 | `i32` | IBUS Average | uA |
| 24 | 4 | `i32` | VBUS Original Avg | uV |
| 28 | 4 | `i32` | IBUS Original Avg | uA |
| 32 | 2 | `i16` | Raw Temperature | - |
| 34 | 2 | `u16` | VCC1 Voltage | 0.1 mV |
| 36 | 2 | `u16` | VCC2 Voltage | 0.1 mV |
| 38 | 2 | `u16` | D+ Voltage | 0.1 mV |
| 40 | 2 | `u16` | D- Voltage | 0.1 mV |
| 42 | 2 | `u16` | Internal VDD | 0.1 mV |
| 44 | 1 | `u8` | **Sample Rate Index** | 0=1, 1=10, 2=50, 3=1k |
| 45 | 1 | `u8` | Unknown/Padding | - |
| 46 | 2 | `u16` | VCC2 Average | 0.1 mV |
| 48 | 2 | `u16` | D+ Average | 0.1 mV |
| 50 | 2 | `u16` | D- Average | 0.1 mV |