# KM003C Protocol Detailed Guide

This document details the USB communication protocol for the ChargerLAB POWER-Z KM003C device. The information has been compiled and verified through analysis of official (but incomplete) documentation, Ghidra reverse engineering of the official Windows application, and USB traffic capture analysis.

## 1. Core Concepts & Transport Layer

The protocol operates over a standard USB Bulk interface, which is presented to the operating system as a Vendor-Specific (WinUSB/libusb) device.

*   **USB Vendor ID (VID):** `0x5FC9` (ChargerLAB)
*   **USB Product ID (PID):** `0x0063` (KM003C)
*   **Host-to-Device Endpoint (OUT):** `0x01`
*   **Device-to-Host Endpoint (IN):** `0x81`

All communication consists of a **4-byte command header**, optionally followed by a data payload. All multi-byte integer values in the protocol are **little-endian**.

## 2. Header Structures and Analysis

The 4-byte header is the fundamental building block of all communication. Its interpretation can vary slightly.

### 2.1. Host-Sent Command Header (Derived from Ghidra)

This structure is based on the `build_command_header @ 14006b470` function in the Windows application, used for constructing commands sent from the host to the device.

```c
QByteArray * build_command_header(QByteArray *param_1, byte param_2, byte param_3)
{
  uint local_res10[2];
  
  QByteArray::QByteArray(param_1);
  DAT_140277089 = DAT_140277089 + 1;  // Global ID counter
  local_res10[0] = ((uint)param_3 << 9 | (uint)DAT_140277089) << 8 | param_2 & 0x7f;
  QByteArray::append(param_1, (char *)local_res10, 4);
  return param_1;
}
```

**Bit Packing Analysis (Host-to-Device):**
- `param_2` = Command Type (7 bits, masked with `0x7f`)
- `param_3` = Attribute (15 bits, shifted left by 9 bits in the construction logic, but represents the raw attribute value)
- `DAT_140277089` = Global ID counter (8 bits, auto-incremented)

**Effective Header Structure (32-bit little-endian word):**
```
Bits:  31...........17  16...........9  8............1  0
       [Attribute (15)] [ID (8 bits)]   [Type (7 bits)] [Enc/Ext (1 bit)]
```
*(Note: The exact position of the 1-bit flag (bit 0 or bit 7) needs further confirmation from device responses or other contexts. `protocol_guessing_old.md` suggests an `extend` bit at bit 7, and `rsvd` at bit 15 of the first word if fields are counted differently. The Ghidra code `param_2 & 0x7f` implies type is in the lowest 7 bits of the first byte, and the `(uint)param_3 << 9` implies attribute starts after type and ID.)*

Corrected interpretation of `local_res10[0] = ((uint)param_3 << 9 | (uint)DAT_140277089) << 8 | param_2 & 0x7f;`:
*   `param_2 & 0x7f`: Command Type (bits 0-6 of the 32-bit word). Bit 7 is `0`.
*   `DAT_140277089`: ID (bits 8-15 of the 32-bit word).
*   `param_3`: Attribute (bits 16-30 of the 32-bit word). Bit 31 is `0`.

**Header Structure (32-bit little-endian word, based on `build_command_header`):**
```
Bits:  31  30...........16  15...........8  7  6...........0
       [0] [Attribute (15)] [ID (8 bits)]   [0] [Type (7 bits)]
```
This means:
- Byte 0: `Type` (7 bits, bit 7 is 0)
- Byte 1: `ID` (8 bits)
- Byte 2: `Attribute` (lower 8 bits)
- Byte 3: `Attribute` (upper 7 bits, bit 31 is 0)

### 2.2. Alternative Header Structure (from `protocol_guessing_old.md`)

This structure was proposed based on earlier analysis:

| Field   | Bits | Description                                                                                           |
| :------ | :--- | :---------------------------------------------------------------------------------------------------- |
| `type`  | 7    | The main command code.                                                                                |
| `extend`| 1    | A flag used for multi-packet data transfers. (Bit 7 of the first byte)                                |
| `id`    | 8    | A transaction ID (0-255), incremented by the host. (Second byte)                                      |
| `rsvd`  | 1    | A reserved bit, observed to be `0` in commands. (Bit 0 of the third byte, or bit 16 overall)           |
| `att`   | 15   | The "Attribute" code. (Bits 1-15 of third byte and all of fourth byte, or bits 17-31 overall)         |

**Note:** These two header descriptions need to be reconciled. The Ghidra-derived structure from `build_command_header` is specific to how the host *sends* simple commands. Device responses or other command types might use different bitfield arrangements. The `extend` bit (for multi-packet) and encryption flags are also important aspects seen in device responses or more complex command headers.

### 2.3. Command Header with Payload (8 bytes, from Ghidra)

From `build_command_header_with_payload @ 14006b9b0`:

```c
QByteArray * build_command_header_with_payload(QByteArray *param_1, ushort param_2, QByteArray *param_3)
{
  // ... 
  DAT_140277089 = DAT_140277089 + 1;
  local_res10[0] = (uint)DAT_140277089 << 8 | 0x48;  // Base command type 0x48
  // Complex payload size calculation for the first 4 bytes of the 8-byte header
  // local_res10[0] = ((int)((payload_size + 3) >> 2) + 2) * 0x400000 | local_res10[0] & 0x3fffff;
  // local_res20[0] = param_2 & 0x7fff;  // Attribute (15 bits)
  // local_res20[0] = (int)payload_size << 0x16 | local_res20[0] & 0x3fffff;
  // Append 8-byte header + payload
}
```

**Key Findings:**
- Commands with payloads use base type `0x48`.
- Uses an 8-byte header structure preceding the actual payload.
- The exact bit packing of this 8-byte header, especially how `payload_size` and the true `type` (like `0x10` for `CMD_SET_CONFIG`) are encoded alongside `0x48` and the `attribute`, needs further detailed analysis from Ghidra. The `local_res10[0]` and `local_res20[0]` parts from the Ghidra output hold the key.

### 2.4. Global State

- `DAT_140277089` @ `140277089`: Global command ID counter, incremented by the host for each new command sent. The device typically echoes this ID in its response.

## 3. Protocol State Machine and Command Sequences

The KM003C is a stateful device. It must be placed into the correct mode before certain commands will work. The official PC application follows a distinct sequence.

### Sequence A: Initial Connection and Handshake

This sequence is required to bring the device online and into a known idle state.

1.  **Host Sends `CMD_CONNECT`:** The host signals its presence.
    *   **Command Example:** `02 01 00 00` (`type=CMD_CONNECT (0x02)`, `id=1`, `att=0`)
    *   The device responds with `CMD_ACCEPT (0x05)` (e.g., `05 01 00 00`).

2.  **Host Performs Authentication (Optional but Recommended):**
    *   `protocol_guessing_old.md` mentioned: "The host sends a series of packets with `type=0x44` and `att` values from `1` to `5`. Each packet contains a long, likely encrypted payload."
    *   This document's "Authentication Protocol Analysis" section (5.4) details `CMD_AUTHENTICATE (0x44)` for simple auth and `CMD_AUTHENTICATE_WITH_PAYLOAD (0x4C)` with `ATT_AUTH (0x0200)` for more advanced, payload-based authentication, which is likely the primary mechanism. This is required for some features like PD Analyzer mode.

3.  **Host Sets Operational Mode:**
    *   **For Data Recorder Mode (VBUS/IBUS logging):**
        *   `protocol_guessing_old.md` suggested: `CMD_AUTHENTICATE_WITH_PAYLOAD (0x4C)` with `att=ATT_ADC_QUEUE (0x0002)` + payload.
        *   This needs verification, as `0x4C` is primarily `CMD_AUTHENTICATE_WITH_PAYLOAD`. It's possible a specific authenticated command sequence sets this mode.
    *   **For PD Analyzer Mode:**
        *   This document (from Ghidra analysis of `set_pd_sniffer_mode`) indicates: `CMD_SET_CONFIG (0x10)` with `attribute=ATT_AUTH (0x0200)`.
        *   (`protocol_guessing_old.md` had an older interpretation involving `CMD_GET_DATA` with attribute `0x0200` or `0x0400`, which seems less likely now).

4.  **Host Settles to Idle:**
    *   A `CMD_STOP_STREAM (0x0F)` command is typically sent (e.g., `0f id 00 00`) to ensure all prior operations are halted.

5.  **Idle Polling (for live dashboard values):**
    *   The host application sends `CMD_GET_DATA (0x0C)` with `att=ATT_ADC (0x0001)` (e.g., `0c id 01 00`) every 200-500ms to receive single ADC data packets.

### Sequence B: High-Speed Data Recording / Charting

This sequence assumes the device is in an idle state after initial connection/authentication.

1.  **Set Sample Rate:**
    *   Uses `CMD_SET_CONFIG (0x10)` with `ATT_SETTINGS (0x0008)`.
    *   **Payload:** A 4-byte little-endian integer representing the sample rate index or value.
        *   Our Ghidra analysis of the UI indicates sample rate indices 0-4 are used:
            *   Index 0: 1 SPS
            *   Index 1: 10 SPS
            *   Index 2: 50 SPS
            *   Index 3: 1 kSPS
            *   Index 4: 10 kSPS
        *   `protocol_guessing_old.md` provided specific 4-byte values for some rates (mapping to an index needs to be confirmed if these are not direct index values):
            *   1 SPS: `01 00 00 00`
            *   10 SPS: `0a 00 00 00`
            *   50 SPS: `32 00 00 00`
            *   1 kSPS (1000 SPS): `e8 03 00 00`
        *   The exact byte payload corresponding to each UI index (0-4) needs to be definitively confirmed. It's likely the 4-byte payload is simply the little-endian representation of the index (0, 1, 2, 3, 4) or one of the specific values listed above.

2.  **Start High-Speed Data Stream:**
    *   Uses `CMD_GET_DATA (0x0C)` with `ATT_ADC_QUEUE (0x0002)`.
    *   **Example Command Bytes (Host to Device):** `0c id 02 00`.
    *   The host must continuously send this command (or the device must be configured for continuous streaming via another setting) to keep receiving data packets.

3.  **Stop High-Speed Data Stream:**
    *   Uses `CMD_STOP_STREAM (0x0F)`.
    *   **Example Command Bytes (Host to Device):** `0f id 00 00`.

### Sequence C: PD Sniffing (PD Analyzer Mode)

1.  **Switch to PD Analyzer Mode:**
    *   Uses `CMD_SET_CONFIG (0x10)` with `attribute=ATT_AUTH (0x0200)`. (This is based on Ghidra analysis of `set_pd_sniffer_mode`).

2.  **Poll for PD Data:**
    *   The host typically alternates polling two different attributes using `CMD_GET_DATA (0x0C)`:
        *   For VBUS/IBUS values: `att=ATT_PD_STATUS (0x0020)`.
        *   For PD protocol packets: `att=ATT_PD_PACKET (0x0010)`.

3.  **Start/Stop Logging to File (in PD Mode):**
    *   **Start:** `CMD_GET_FILE (0x0E)` (likely with `attribute=0` or a specific PD logging attribute). Example: `0e id 00 00`.
    *   **Stop:** `CMD_STOP_STREAM (0x0F)` (likely with `attribute=0`). Example: `0f id 00 00`.

## 4. ADC Sensor Data Packet Structure

This is the 52-byte packet returned by the device in Data Recorder mode (e.g., in response to `CMD_GET_DATA` with `ATT_ADC` or `ATT_ADC_QUEUE`). All multi-byte values are little-endian.

| Offset (bytes) | Length (bytes) | Data Type | Description        | Unit    |
| :------------- | :------------- | :-------- | :----------------- | :------ |
| 0              | 4              | Header    | Response Header    | -       |
| 4              | 4              | Header    | Extended Header    | -       |
| 8              | 4              | `int32_t` | VBUS Voltage       | µV      |
| 12             | 4              | `int32_t` | IBUS Current       | µA      |
| 16             | 4              | `int32_t` | VBUS Average       | µV      |
| 20             | 4              | `int32_t` | IBUS Average       | µA      |
| 24             | 4              | `int32_t` | VBUS Original Avg  | µV      |
| 28             | 4              | `int32_t` | IBUS Original Avg  | µA      |
| 32             | 2              | `int16_t` | Raw Temperature    | -       |
| 34             | 2              | `uint16_t`| VCC1 Voltage       | 0.1 mV  |
| 36             | 2              | `uint16_t`| VCC2 Voltage       | 0.1 mV  |
| 38             | 2              | `uint16_t`| D+ Voltage         | 0.1 mV  |
| 40             | 2              | `uint16_t`| D- Voltage         | 0.1 mV  |
| 42             | 2              | `uint16_t`| Internal VDD       | 0.1 mV  |
| 44             | 1              | `uint8_t` | Sample Rate Index  | 0=1, 1=10, 2=50, 3=1k SPS |
| 45             | 1              | `uint8_t` | Unknown/Padding    | -       |
| 46             | 2              | `uint16_t`| VCC2 Average       | 0.1 mV  |
| 48             | 2              | `uint16_t`| D+ Average         | 0.1 mV  |
| 50             | 2              | `uint16_t`| D- Average         | 0.1 mV  |

*(Note: The Sample Rate Index at offset 44 is particularly interesting. Our Ghidra UI analysis suggests indices 0-4 for 1, 10, 50, 1k, 10k SPS. This table only lists up to index 3 for 1k SPS. This needs reconciliation or confirmation if 10kSPS ADC data uses a different packet or if this table is incomplete for higher rates).*

## 5. Detailed Command Analysis & Protocol Aspects

### 5.1. Command Type Table

| Value | Name | Source | Description |
|-------|------|--------|-------------|
| 0x02 | CMD_CONNECT | Known | Initial handshake |
| **0x03** | **CMD_DISCONNECT** | **NEW!** | Disconnect command |
| 0x05 | CMD_ACCEPT | Known | Positive acknowledgment |
| **0x08** | **CMD_JUMP_APROM** | **NEW!** | Jump to application ROM |
| **0x09** | **CMD_JUMP_DFU** | **NEW!** | Jump to DFU/bootloader |
| 0x0C | CMD_GET_DATA | Known | Data request |
| **0x0E** | **CMD_GET_FILE** | **NEW!** | Start data stream |
| **0x0F** | **CMD_STOP_STREAM** | **NEW!** | Stop data stream |
| **0x10** | **CMD_SET_CONFIG** | **NEW!** | Set configuration |
| **0x11** | **CMD_RESET_CONFIG** | **NEW!** | Reset configuration |
| **0x40** | **CMD_GET_DEVICE_INFO** | **NEW!** | Get device information block |
| 0x41 | StatusA | Known | Device response type |
| **0x43** | **CMD_SERIAL** | **NEW!** | Serial/text command |
| 0x44 | CMD_AUTHENTICATE | Known | Authentication (simple) |
| 0x48 | CMD_DATA_WITH_PAYLOAD | NEW! | Base type for payload commands |
| **0x4C** | **CMD_AUTHENTICATE_WITH_PAYLOAD** | **NEW!** | Authentication with encrypted payload. May also be used with specific attributes (e.g., `ATT_ADC_QUEUE (0x0002)`) for functions like setting data recorder mode, as suggested by earlier analyses. |

### 5.2. Attribute Table

| Value | Name | Source | Description |
|-------|------|--------|-------------|
| 0x0001 | ATT_ADC | Known | Single ADC reading |
| 0x0002 | ATT_ADC_QUEUE | Known | Continuous ADC stream |
| 0x0008 | ATT_SETTINGS | Known | Configuration data |
| 0x0010 | ATT_PD_PACKET | Known | PD protocol packets |
| 0x0020 | ATT_PD_STATUS | Known | PD status data |
| 0x0040 | ATT_QC_PACKET | NEW! | QC protocol packets |
| 0x0080 | ATT_TIMESTAMP | NEW! | Timestamp/status data |
| **0x0180** | **ATT_SERIAL** | **NEW!** | Serial command attribute |
| **0x0200** | **ATT_AUTH** | **NEW!** | Primarily the attribute for `CMD_AUTHENTICATE_WITH_PAYLOAD (0x4C)`. Also used with `CMD_SET_CONFIG (0x10)` to switch to PD Analyzer mode. *(Earlier analyses suggested it might be used with `CMD_GET_DATA` for mode switching, but current Ghidra RE points to `CMD_SET_CONFIG`)*. |
| **0x1000** | **ATT_DEVICE_INFO** | **NEW!** | Device information attribute |

### 5.3. Command Analysis by Category

#### Basic Communication Commands

##### CMD_CONNECT (0x02)
From `send_simple_command @ 14006ec70`:
- Initial handshake command
- Uses `attribute = 0` for simple commands
- 1000ms timeout for response

##### CMD_DISCONNECT (0x03) - **MAJOR DISCOVERY**
From `handle_response_packet @ 14006d1b0`:
```c
else if ((uVar1 & 0x7f) == 3) {
  QDebug::operator<<(pQVar9, "CMD_DISCONNECT");
}
```
- Explicitly handled in response parser
- This was the unknown command 0x03 mentioned in the original task!

##### CMD_ACCEPT (0x05)
- Standard positive acknowledgment from device
- Returned in response to successful commands

#### Data Stream Management Commands

##### CMD_GET_DATA (0x0C)
- Primary command to request data from device
- Attribute determines data type (ADC, PD packets, etc.)

##### CMD_GET_FILE (0x0E) / CMD_STOP_STREAM (0x0F)
From `manage_data_stream @ 14006f032`:
```c
// Stop stream command
build_command_header(local_88, 0xf, 0);  // CMD_STOP_STREAM = 0x0F

// Start data stream command  
build_command_header(local_70, 0xe, QVar7);  // CMD_GET_FILE = 0x0E (repurposed for streaming)
```
- **0x0E**: Start data stream (repurposed from "get file")
- **0x0F**: Stop any active data stream

#### Configuration Commands

##### CMD_SET_CONFIG (0x10) / CMD_RESET_CONFIG (0x11)
- **`CMD_SET_CONFIG (0x10)`**: Sets various device configurations.
    - **Setting Sample Rate:**
        - Used with `Attribute = ATT_SETTINGS (0x0008)`.
        - **Payload:** A 4-byte little-endian integer. The exact nature of this integer (direct rate, index, or specific value) is based on UI analysis and `protocol_guessing_old.md`.
        - Our Ghidra analysis of the UI indicates sample rate indices 0-4 are used:
            - Index 0: 1 SPS
            - Index 1: 10 SPS
            - Index 2: 50 SPS
            - Index 3: 1 kSPS
            - Index 4: 10 kSPS
        - The payload is likely the 4-byte little-endian representation of this index (0, 1, 2, 3, or 4).
        - `protocol_guessing_old.md` provided specific 4-byte values for some rates, which might correspond to these indices or be an alternative way of encoding:
            - For 1 SPS: `01 00 00 00`
            - For 10 SPS: `0a 00 00 00`
            - For 50 SPS: `32 00 00 00`
            - For 1 kSPS (1000 SPS): `e8 03 00 00`
        - **Example (Conceptual):** To set 10 SPS (index 1), the command might be `10 id 08 00` + `01 00 00 00` (if payload is index) or `0a 00 00 00` (if payload is specific value). This requires sending via `CMD_DATA_WITH_PAYLOAD (0x48)` mechanism or ensuring `build_command_header_with_payload` is used.
    - **Setting PD Sniffer Mode:**
        - Used with `Attribute = ATT_AUTH (0x0200)` (as seen in `set_pd_sniffer_mode @ 14006ee32` from Ghidra). This command does not use a complex payload in this specific case, rather the attribute itself dictates the mode switch.
        - Example from `set_pd_sniffer_mode`: `build_command_header(local_78, 0x10, 0x0200);` (if `param_1[0x255]` is `0x0200`).

- **`CMD_RESET_CONFIG (0x11)`**: Resets configuration, notably used to turn off PD sniffer mode.
    - Example from `set_pd_sniffer_mode`: `build_command_header(local_60, 0x11);` (likely with attribute 0).
From `set_pd_sniffer_mode @ 14006ee32` (illustrating PD sniffer mode toggle):
```c
// To enable PD Sniffer (assuming param_1[0x255] holds ATT_AUTH (0x0200))
build_command_header(local_78, 0x10, param_1[0x255]); // CMD_SET_CONFIG = 0x10, attr = 0x0200

// To disable PD Sniffer / reset
build_command_header(local_60, 0x11); // CMD_RESET_CONFIG = 0x11
```

#### Firmware/Bootloader Commands

##### CMD_JUMP_APROM (0x08) / CMD_JUMP_DFU (0x09)
From `jump_to_bootloader_or_app @ 14006df3e`:
```c
bVar2 = QString::operator==(local_38, "APP");
if (bVar2) {
  uVar1 = build_command_header(local_20, 9, 0);  // CMD_JUMP_DFU = 0x09
} else {
  uVar1 = build_command_header(local_20, 8, 0);  // CMD_JUMP_APROM = 0x08
}
```
- **0x08**: Jump to application ROM
- **0x09**: Jump to DFU/bootloader mode
- Logic: If device reports "APP" interface, jump to DFU; otherwise jump to APROM

#### Device Information Command

##### CMD_GET_DEVICE_INFO (0x40)
From `get_info_block @ 14006de50` and `FUN_14006b580`:
```c
// Build device info request command
DAT_140277089 = DAT_140277089 + 1;
local_res10[0] = (uint)DAT_140277089 << 8 | 0x1000040;
QByteArray::append(param_1, (char *)local_res10, 4);
QByteArray::append(param_1, 0x10, '\0');  // 16 zero bytes padding
```
- Returns 200+ byte device information block
- Contains firmware version, capabilities, device name, calibration data

### 5.4. Authentication Protocol Analysis

Authentication in the KM003C protocol involves both a simple handshake and a more complex challenge-response mechanism using encryption.

#### Simple Authentication (`CMD_AUTHENTICATE (0x44)`)
- This command is used for basic authentication steps, likely without a substantial or encrypted payload.
- It's part of the initial handshake sequence to verify the host and device.
- `protocol_guessing_old.md` noted that during initial connection, the host sends a series of packets with `type=0x44` and attributes from `1` to `5`, possibly as part of a multi-step simple handshake.

#### Advanced Authentication (`CMD_AUTHENTICATE_WITH_PAYLOAD (0x4C)`, `ATT_AUTH (0x0200)`)
This is a more robust challenge-response mechanism involving AES encryption, typically managed by the host function `send_auth_packet_and_verify @ 14006e9e0` for each step of the authentication process.

##### Overall Flow (per authentication step):

1.  **Challenge Payload Construction (Host-Side, within `send_auth_packet_and_verify`):**
    *   A plaintext challenge payload is assembled. This typically includes:
        *   An 8-byte current timestamp (e.g., from `QDateTime::toMSecsSinceEpoch()`).
        *   Conditional data that may vary depending on the authentication step (`param_2` of `send_auth_packet_and_verify`). This data might be sourced from device-specific information or previous auth step results stored in the host's connection object.
        *   An 8-byte random nonce (e.g., from `QRandomGenerator`).
    *   The typical size of this plaintext challenge payload before encryption is 32 bytes.

2.  **Command Construction & Encryption (Host-Side, by `FUN_14006b860` / `build_encrypted_auth_command`):**
    *   This function is called by `send_auth_packet_and_verify`.
    *   It constructs the 4-byte command header:
        *   Type: `CMD_AUTHENTICATE_WITH_PAYLOAD (0x4C)`
        *   Attribute: `ATT_AUTH (0x0200)`
        *   ID: Current global incrementing ID.
    *   It retrieves a 16-byte AES key using `get_crypto_key(@1400735e0, 3)`. The key itself is hardcoded (see Key Management below).
    *   The plaintext challenge payload (from step 1) is encrypted using this AES key (AES-128, likely CBC mode 3). **Crucially, for encryption, the key obtained from `get_crypto_key` is used directly without modification.**
    *   The resulting 32-byte ciphertext is appended to the 4-byte command header.

3.  **Transmission to Device:**
    *   The complete 36-byte packet (4-byte header + 32-byte encrypted payload) is sent to the KM003C device.

4.  **Response Reception & Decryption (Host-Side, within `send_auth_packet_and_verify`):**
    *   The device responds, typically with a packet also of type `0x4C` and containing an encrypted payload.
    *   The host again calls `get_crypto_key(@1400735e0, 3)` to retrieve the same base AES key (see Key Management below for value).
    *   **Key Modification for Decryption:** Before using the key for decryption, the host modifies it: the second byte (index 1) of the 16-byte key is overwritten with the ASCII value 'X' (`0x58`).
    *   The encrypted payload from the device's response (typically 32 bytes, after the 4-byte response header) is decrypted using this *modified* key and AES (likely CBC mode 3).

5.  **Response Verification (Host-Side):**
    *   The decrypted response payload is verified. It is expected to contain:
        *   The original 8-byte timestamp sent in the challenge.
        *   The original 8-byte random nonce sent in the challenge (typically found at offset 0x18, or 24 bytes, in the decrypted payload, assuming 16 bytes of other data from the device).
    *   If the timestamp and nonce match, the authentication step is considered successful, and a status flag is updated in the host's connection object.

##### Key Management (`get_crypto_key @ 1400735e0`):
-   This function returns one of at least four distinct 16-byte AES keys.
-   The keys are hardcoded directly in the application's data segment at fixed memory addresses. The actual byte values have been extracted (see `docs/ghidra.md` for details and exact values):
    *   **Key Index 0:** `4c6832796642376e365837643961355a` (from VA `0x140184adc`)
    *   **Key Index 1:** `73646b57373852336b35646a30664876` (from VA `0x140184b06`)
    *   **Key Index 2:** `5793334565731336a486a3335393865` (from VA `0x140184b35`)
    *   **Key Index 3 (Primary Auth):** `46613062347441323566345230333861` (from VA `0x140184b76`)
-   The specific key used for the main authentication flow (`param_2 = 3` in `get_crypto_key`) is Key Index 3.
-   **The actual byte values of these hardcoded keys are critical for any library implementation.**

##### Summary of Involved Functions:
-   **`send_auth_packet_and_verify @ 14006e9e0`**: Orchestrates a single challenge-response step.
-   **`FUN_14006b860` (`build_encrypted_auth_command`)**: Constructs and encrypts the outgoing command.
-   **`get_crypto_key @ 1400735e0`**: Provides the hardcoded AES keys.

### 5.5. Serial Command Protocol Analysis

#### **MAJOR DISCOVERY: Text Command Encapsulation**

From `build_serial_command_packet @ 14006bd10`:

```c
void build_serial_command_packet(QByteArray *param_1, QString *param_2)
{
  // Header construction
  DAT_140277089 = DAT_140277089 + 1;
  local_a4 = (uint)DAT_140277089 << 8 | 0x1800043;
  QByteArray::append(param_1, (char *)&local_a4, 4);
  
  // Fixed 8-byte payload header
  local_a0[0] = '\0';   // 0x00
  local_a0[1] = '\f';   // 0x0C  
  local_a0[2] = '\0';   // 0x00
  local_a0[3] = '\x03'; // 0x03
  local_a0[4] = '<';    // 0x3C
  local_a0[5] = '\0';   // 0x00
  local_a0[6] = '\0';   // 0x00
  local_a0[7] = '\0';   // 0x00
  QByteArray::append(param_1, local_a0, 8);
  
  // Command string + metadata
  QByteArray::append(param_1, QString::toLocal8Bit(param_2));  // The actual command
  QByteArray::append(param_1, ' ');
  QByteArray::append(param_1, QUuid::createUuid().toString().toUpper());  // UUID
  QByteArray::append(param_1, ' ');
  QByteArray::append(param_1, QByteArray::number(QDateTime::currentDateTimeUtc().toSecsSinceEpoch()));  // Timestamp
  QByteArray::append(param_1, ' ');
  QByteArray::append(param_1, '\0');
  QByteArray::append(param_1, "LYS");  // Magic suffix
}
```

##### Serial Command Structure

**Header Analysis:**
- Command: `0x1800043` = `0x01800000 | 0x43`
- Command type: `0x43` (CMD_SERIAL)
- Attribute: `0x0180` (ATT_SERIAL)

**Fixed Payload Header (8 bytes):**
```
00 0C 00 03 3C 00 00 00
```

**Complete Command Format:**
```
[4-byte header] [8-byte fixed payload] [command_string] [space] [UUID] [space] [timestamp] [space] [null] "LYS"
```

**Example Serial Command Packet:**
For command "pdm open":
```
Header: 43 XX 80 01  (where XX is incremented ID)
Fixed:  00 0C 00 03 3C 00 00 00
Data:   "pdm open {UUID} {timestamp} \0LYS"
```

This explains how text commands like "pdm open", "pd pdo", "entry pd" etc. are encapsulated in the binary protocol!

### 5.6. Response Packet Analysis

From `handle_response_packet @ 14006d1b0`:

#### Response Processing Logic

```c
puVar7 = (uint *)QByteArray::constData(local_108);
uVar1 = *puVar7;  // Read 4-byte header

if ((uVar1 & 0x7f) == 0x41) {
  // Handle StatusA response (0x41)
  // Complex data processing with optional decryption
}
else if ((uVar1 & 0x7f) == 3) {
  // Handle CMD_DISCONNECT (0x03)
  QDebug::operator<<(pQVar9, "CMD_DISCONNECT");
}
```

#### Response Attribute Processing

The function processes different attribute types:

- **Attribute 0x01 (ATT_ADC)**: Calls `FUN_14006c9c0` for sensor data processing
- **Attribute 0x02 (ATT_ADC_QUEUE)**: Handles queued sensor data with chunk processing
- **Attribute 0x08 (ATT_SETTINGS)**: Processes 96-byte + 84-byte configuration data
- **Attribute 0x10 (ATT_PD_PACKET)**: PD packet processing with size validation
- **Attribute 0x20 (ATT_PD_STATUS)**: PD status data
- **Attribute 0x40**: QC packet data (likely Qualcomm Quick Charge)
- **Attribute 0x80**: Stores timestamp and status byte
- **Attribute 0x200**: PD analyzer mode data storage

#### Encryption Support

The device supports encrypted responses:
- Bit 16 of header indicates encrypted data
- Uses AES decryption with 16-byte key
- Crypto mode 3 (likely CBC or similar)

### 5.7. HID Interface Analysis

#### **MAJOR DISCOVERY: Multi-Interface Support Confirmed**

From `initialize_device_session @ 140069dd7` and endpoint functions:

##### Multi-Interface Architecture

```c
// The app claims ALL available interfaces
libusb_claim_interface(*(undefined8 *)(param_1 + 0x70), *local_e8);

// Endpoint selection logic in write_data_to_endpoint:
if (((*(uint *)(lVar2 + 8) >> 8 & 0xff) == param_2) &&
   (cStack_37 = (char)((uint)*(undefined4 *)(lVar2 + 8) >> 8), cStack_37 == '\x03')) {
    // Use INTERRUPT transfer (HID interface)
    libusb_interrupt_transfer(...)
}
else if (((*(uint *)(lVar2 + 8) >> 8 & 0xff) == param_2) &&
        (cStack_2b = (char)((uint)*(undefined4 *)(lVar2 + 8) >> 8), cStack_2b == '\x02')) {
    // Use BULK transfer (Vendor/CDC interface)  
    libusb_bulk_transfer(...)
}
```

##### Key Findings

1. **Interface Detection:** The app automatically detects and claims ALL available interfaces (0, 1, 2, 3)

2. **Dynamic Endpoint Selection:** Based on endpoint type:
   - **Type 0x03 (Interrupt)** → Uses `libusb_interrupt_transfer` → **HID Interface**
   - **Type 0x02 (Bulk)** → Uses `libusb_bulk_transfer` → **Vendor Interface**

3. **Protocol Compatibility:** The same command protocol works across ALL interfaces - the app just switches transfer methods automatically

4. **Fallback Strategy:** If one interface fails, the app can fall back to others

##### Interface Usage Summary

| Interface | Class | Endpoints | Transfer Type | Usage |
|-----------|-------|-----------|---------------|--------|
| 0 | 0xFF (Vendor) | 0x01/0x81 | Bulk | **Primary high-speed interface** |
| 1 | 0x02 (CDC) | 0x83 | Interrupt | Serial port control |
| 2 | 0x0A (CDC Data) | 0x02/0x82 | Bulk | Serial port data |
| 3 | 0x03 (HID) | 0x05/0x85 | Interrupt | **Driver-free fallback** |

##### Answer to Original Question

**YES, the Windows app DOES use HID!** It's implemented as:
- **Automatic fallback** when vendor drivers aren't available
- **Same protocol** as vendor interface (same 4-byte headers, same commands)
- **64-byte packet limit** (as documented)
- **Interrupt transfers** instead of bulk transfers

Your current implementation uses only the vendor interface (0xFF), but the Windows app is more robust - it supports all 4 interfaces and automatically selects the best available one.

### 5.8. Device Information Block Analysis

#### Large Device Info Response (200+ bytes)

From Wireshark capture analysis and `get_info_block @ 14006de50`:

##### Command Structure
```c
// Build device info request command
DAT_140277089 = DAT_140277089 + 1;
local_res10[0] = (uint)DAT_140277089 << 8 | 0x1000040;
QByteArray::append(param_1, (char *)local_res10, 4);
QByteArray::append(param_1, 0x10, '\0');  // 16 zero bytes padding
```

##### Wireshark Capture Analysis
```
Frame 760: Host -> Device: 0c071000  (CMD_GET_DATA with ATT_DEVICE_INFO)
Frame 762: Device -> Host: 4107020b0800002d610150f8... (200+ byte response)
```

##### Device Info Block Structure

From the hex data in frame 762:
```
4107020b0800002d610150f800000000102741ff00000000fffffffffffffffffffffffffafffffffafffffffafffffffafffffffaffffffed4a0f00ed4a0f00ed4a0f00ed4a0f00ed4a0f00ed4a0f00ed4a0f00ed4a0f00ed4a0f00ed4a0f005e000000268bb83a40000000000000000000000000000000504f5745522d5a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001fd56df6
```

**Decoded Fields:**

| Offset | Length | Value | Interpretation |
|--------|--------|-------|----------------|
| 0-3 | 4 | `4107020b` | Response header |
| 4-7 | 4 | `0800002d` | Size/flags |
| 8-11 | 4 | `610150f8` | **Firmware version** |
| 12-15 | 4 | `00000000` | Reserved |
| 16-19 | 4 | `102741ff` | **Device capabilities** |
| 20-23 | 4 | `00000000` | Reserved |
| 24-39 | 16 | `ffffffff...` | Calibration data |
| 40-79 | 40 | `faffffff...` | ADC configuration |
| 80-119 | 40 | `ed4a0f00...` | Repeated pattern (calibration) |
| 120-123 | 4 | `5e000000` | Counter/status |
| 124-127 | 4 | `268bb83a` | Timestamp |
| 128-135 | 8 | `40000000...` | Reserved |
| 136-199 | 64 | `504f5745522d5a...` | **"POWER-Z" string + padding** |
| 200-203 | 4 | `1fd56df6` | Checksum/CRC |

##### Key Findings

1. **Device Name:** Clear "POWER-Z" string at offset 136
2. **Firmware Info:** At offset 8-11 (`610150f8`)
3. **Capabilities:** Capability flags at offset 16-19
4. **Calibration Data:** Large blocks of structured data
5. **Checksum:** Final 4 bytes likely CRC or checksum

##### Usage in Application

The device info block is requested during initialization:
1. **After authentication** completes successfully
2. **Before starting** normal data polling
3. **To determine** device capabilities and configuration

## 6. Implementation Recommendations

### For Enhanced Rust Library

1. **Add Multi-Interface Support:** Detect and try interfaces in order: Vendor → CDC → HID
2. **Automatic Fallback:** If vendor interface fails, fall back to HID
3. **Cross-Platform Compatibility:** HID works without drivers on all platforms
4. **Device Info Parsing:** Create DeviceInfo struct to parse the 200+ byte response
5. **Serial Command Support:** Implement CMD_SERIAL for text-based protocol commands
6. **Dynamic Authentication:** Enhance beyond hardcoded replay approach

### Missing Commands to Implement

- **CMD_DISCONNECT (0x03)** - Proper device disconnection
- **CMD_STOP_STREAM (0x0F)** - Stop any active data streams
- **CMD_SET_CONFIG (0x10)** - Device configuration
- **CMD_GET_DEVICE_INFO (0x40)** - Device information block
- **CMD_SERIAL (0x43)** - Text command encapsulation

## 7. Next Analysis Targets

Functions to examine next:
- `FUN_14006c9c0` - ADC data processing function  
- `FUN_140161150` - PD packet processing function
- `get_crypto_key` - Crypto key management
- Device info parsing and field extraction logic

</final_file_content>

IMPORTANT: For any future changes to this file, use the final_file_content shown above as your reference. This content reflects the current state of the file, including any auto-formatting (e.g., if you used single quotes but the formatter converted them to double quotes). Always base your SEARCH/REPLACE operations on this final version to ensure accuracy.<environment_details>
# VSCode Visible Files
docs/protocol.md

# VSCode Open Tabs
src/bin/capture.rs
docs/llm.md
docs/ghidra.md
docs/todo.md
docs/protocol.md
src/bin/endpoints.rs

# Current Time
6/19/2025, 7:22:34 AM (Europe/Moscow, UTC+3:00)

# Context Window Usage
734,402 / 1,048.576K tokens used (70%)

# Current Mode
ACT MODE
</environment_details>
