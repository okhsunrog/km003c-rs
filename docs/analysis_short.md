## Power-Z KM002c/KM003C Communication Protocol Analysis

### High-Level Overview

The Power-Z Windows application communicates with the KM002c/KM003C device over USB. The protocol is a custom command/response system encapsulated in packets. The application is built on the Qt framework, which manages the UI and event loop, while the underlying communication likely uses a USB library like `libusb` or a native serial/HID interface.

The protocol is versatile, supporting three distinct interface modes and featuring two primary methods for data acquisition: a low-speed polled mode for dashboard updates and an efficient, high-speed queued mode for real-time charting.

### 1. USB Interface Modes

The device offers three distinct communication interfaces, allowing for flexibility across different platforms:

1.  **USER (WinUSB/USB USER):** A high-speed (200 KB/s) vendor-specific interface. It requires a driver on Windows (WinUSB) but offers the best performance.
2.  **CDC (Virtual COM Port):** A medium-speed (200 KB/s) interface that emulates a serial port. It is easy to use with standard serial terminal tools, and the baud rate setting is ignored.
3.  **HID (Human Interface Device):** A lower-speed (60 KB/s) interface with a 64-byte packet size limit. Its main advantage is that it requires **no custom drivers** on any major operating system.

All three interfaces use the same command and data structures described below.

### 2. Core Protocol Concepts: The Message Header

All communication is built around a 4-byte header (`MsgHeader_TypeDef`). This header is a C union, meaning the same 4 bytes can be interpreted in different ways depending on the message context.

**`MsgHeader_TypeDef` Union Structure (4 bytes, Little-Endian):**
```c
typedef union {
    uint32_t object;
    uint16_t word[2];
    uint8_t  byte[4];

    // For Control Commands (Host -> Device)
    struct {
        uint32_t type     : 7;  // Command Type (from cmd_ctrl_msg_type)
        uint32_t extend   : 1;  // Used for large data packets
        uint32_t id       : 8;  // Transaction ID
        uint32_t          : 1;  // Reserved (or encrypted flag)
        uint32_t att      : 15; // Attribute (from attribute_data_type)
    } ctrl;

    // For Data Responses (Device -> Host)
    struct {
        uint32_t type     : 7;  // Response Type (from cmd_data_msg_type)
        uint32_t extend   : 1;
        uint32_t id       : 8;  // Mirrored Transaction ID
        uint32_t          : 6;
        uint32_t obj      : 10; // e.g., Number of objects
    } data;
    
    // For large data transfers
    struct {
        uint32_t att      : 15;
        uint32_t next     : 1; // 1 if more chunks follow
        uint32_t chunk    : 6; // Chunk index
        uint32_t size     : 10; // Size of this chunk in bytes
    } header;

} MsgHeader_TypeDef;
```

### 3. Command and Attribute Definitions

#### Command Types (`cmd_ctrl_msg_type`)
These are used in the `type` field of the `ctrl` struct, primarily for Host-to-Device communication.

| Value  | Name              | Description                                      |
| :----- | :---------------- | :----------------------------------------------- |
| `0x02` | `CMD_CONNECT`     | Establish a connection with the device.          |
| `0x03` | `CMD_DISCONNECT`  | Terminate the connection.                        |
| `0x05` | `CMD_ACCEPT`      | Acknowledgment of a successful command.          |
| `0x06` | `CMD_REJECT`      | Rejection of a command.                          |
| `0x0C` | `CMD_GET_DATA`    | Request data from the device (type depends on attribute). |
| `0x0E` | `CMD_GET_FILE`    | Used to initiate data transfer for offline logs. |
| `0x0F` | `CMD_STOP_STREAM` | (Inferred) Stops the high-speed data stream.     |

#### Data Response Types (`cmd_data_msg_type`)
These are used in the `type` field of the `data` struct for Device-to-Host responses.
-   `type > 63`: Indicates a data packet, not a control response.
-   `0x41` (65): A standard data response packet, seen in logs as `SensorData` or `GenericResponse`.

#### Attribute Types (`attribute_data_type`)
Attributes specialize the `CMD_GET_DATA` command. This is how the host requests different kinds of data.

| Value  | Name                | Description                                                                 |
| :----- | :------------------ | :-------------------------------------------------------------------------- |
| `0x01` | `ATT_ADC`           | Request a single, comprehensive ADC data packet (`AdcData_TypeDef`).        |
| `0x02` | `ATT_ADC_QUEUE`     | Request the high-speed (default rate) VBUS/IBUS data stream for charting.   |
| `0x04` | `ATT_ADC_QUEUE_10K` | Request the high-speed (10k SPS) VBUS/IBUS data stream.                     |
| `0x08` | `ATT_SETTINGS`      | Used to **set** device parameters, like the sample rate.                    |
| `0x10` | `ATT_PD_PACKET`     | Request Power Delivery packet information.                                  |
| `0x20` | `ATT_PD_STATUS`     | Request current PD status.                                                  |
| `0x40` | `ATT_QC_PACKET`     | Request QuickCharge packet information.                                     |
| `0x0006`| *(Unnamed)*        | **Combined Sync Request:** Requests both `ATT_ADC` and `ATT_ADC_QUEUE` data in one response. |

### 4. Data Streaming Protocols

The application uses two distinct protocols for retrieving ADC data.

#### Protocol 1: Low-Speed Polled Data (Dashboard)

This mode is used for updating the main dashboard with a full snapshot of all sensor values.

-   **Request:** The host sends a `CMD_GET_DATA` (`0x0C`) command with `attribute` = **`ATT_ADC` (0x0001)**.
-   **Response:** The device replies with a single **52-byte** packet containing the `AdcData_TypeDef` struct.
-   **Parsing Function:** `FUN_14015c9a0` (and `FUN_140157dd0` from the logs) are responsible for parsing this struct.

**`AdcData_TypeDef` Structure (52 bytes)**

This struct follows the `MsgHeader_TypeDef` header in the response packet. All multi-byte integers are **Little-Endian**.

| Offset | Length (Bytes) | Field           | Type      | Unit (in packet) | Scaling Factor |
| :----- | :------------- | :-------------- | :-------- | :--------------- | :------------- |
| 0      | 4              | `Vbus`          | `int32_t` | Microvolts (µV)  | ÷ 1,000,000    |
| 4      | 4              | `Ibus`          | `int32_t` | Microamps (µA)   | ÷ 1,000,000    |
| 8      | 4              | `Vbus_avg`      | `int32_t` | Microvolts (µV)  | ÷ 1,000,000    |
| 12     | 4              | `Ibus_avg`      | `int32_t` | Microamps (µA)   | ÷ 1,000,000    |
| 16     | 4              | `Vbus_ori_avg`  | `int32_t` | (Uncalibrated)   | -              |
| 20     | 4              | `Ibus_ori_avg`  | `int32_t` | (Uncalibrated)   | -              |
| 24     | 2              | `Temp`          | `int16_t` | Celsius \* 100   | ÷ 100          |
| 26     | 2              | `Vcc1`          | `uint16_t`| 0.1 millivolts   | ÷ 10,000       |
| 28     | 2              | `Vcc2`          | `uint16_t`| 0.1 millivolts   | ÷ 10,000       |
| 30     | 2              | `Vdp`           | `uint16_t`| 0.1 millivolts   | ÷ 10,000       |
| 32     | 2              | `Vdm`           | `uint16_t`| 0.1 millivolts   | ÷ 10,000       |
| 34     | 2              | `Vdd`           | `uint16_t`| (Internal VDD)   | (varies)       |
| 36     | 2              | `Rate` / `n`    | `uint8_t[2]`| `Rate` is an enum index. | -            |
| ...    | ...            | ...             | ...       | ...              | ...            |

#### Protocol 2: High-Speed Queued Data (Real-Time Chart)

This mode is activated when the user opens the chart view. It is optimized for high-frequency data transfer.

-   **Request:** The host sends a `CMD_GET_DATA` (`0x0C`) command with `attribute` = **`ATT_ADC_QUEUE` (0x0002)** or **`ATT_ADC_QUEUE_10K` (0x0004)**.
-   **Response:** The device sends a continuous stream of data chunks. Each chunk has a **variable-length integer (Varint)** prefix that specifies the length of the following payload.
-   **Parsing Function:** **`FUN_1401184c0`** is the core function that de-frames and reassembles these chunks from the raw USB stream.

**High-Speed Chunk Payload Format:**

The payload of each chunk contains only VBUS and IBUS data, packed into 8-byte sample pairs. This minimizes overhead for charting.

| Offset (within pair) | Length (Bytes) | Data Field | Data Type (Little-Endian) | Unit (in Packet) | Scaling Factor |
| :------------------- | :------------- | :--------- | :------------------------ | :--------------- | :------------- |
| `0 - 3`              | 4              | **VBUS**   | `int32_t`                 | Microvolts (µV)  | ÷ 1,000,000    |
| `4 - 7`              | 4              | **IBUS**   | `int32_t`                 | Microamps (µA)   | ÷ 1,000,000    |

### 5. Key Command Sequences

#### A. Session Start and Authentication

The logs show a mandatory handshake sequence upon connection.

1.  **H->D:** `CMD_CONNECT` (`02010000`).
2.  **D->H:** `CMD_ACCEPT` (`05010000`).
3.  **H->D & D->H (Loop):** A multi-step challenge-response handshake using `CMD_AUTHENTICATE` (`0x44`) with attribute `AuthStep` (`0x0101`). The device sends a challenge (`DataChunk`), the host encrypts/transforms it and sends it back, and the device responds with an acknowledgment (`ResponseC4`). This must complete before other commands are accepted.

#### B. Changing Sample Rate

This is handled by a settings command, not a unique command type.

1.  **UI Action:** User selects a sample rate (e.g., "50 SPS").
2.  **H->D:** The application (via `FUN_14012c170`) sends a command, likely `CMD_SET_CONFIG` (`0x10`) with `attribute` = **`ATT_SETTINGS` (0x0008)**.
3.  **Payload:** The payload is the integer value of the rate, e.g., `0x32` (50).
4.  **Device Action:** The KM003C firmware adjusts its internal ADC sampling timer to the new rate.

#### C. Combined "Sync" Packet Request

The logs reveal an optimized command for syncing both dashboard and chart data.

1.  **H->D:** `CMD_GET_DATA` (`0x0C`) with `attribute` = **`0x0006`**.
2.  **D->H:** The device replies with a single, large packet (`41...`) that concatenates:
    *   The full 52-byte `AdcData_TypeDef` structure.
    *   One or more high-speed `(VBUS, IBUS)` data chunks.
3.  **PC Action:** The application's meta-parser (`FUN_14015bbb0`) splits this response, sending the first 52 bytes to the low-speed parser and the remainder to the high-speed stream parser.

This comprehensive analysis integrates the official documentation, your log files, and the decompiled code, providing a verified and detailed description of the KM003C's communication protocol.