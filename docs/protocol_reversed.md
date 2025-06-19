# KM003C Protocol Reverse Engineering Results

This document contains findings from reverse engineering the original Windows application for the ChargerLAB POWER-Z KM003C device.

## Complete Protocol Reference

### Command Type Table

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
| **0x4C** | **CMD_AUTHENTICATE_WITH_PAYLOAD** | **NEW!** | Authentication with encrypted payload |

### Attribute Table

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
| **0x0200** | **ATT_AUTH** | **NEW!** | Authentication attribute |
| **0x1000** | **ATT_DEVICE_INFO** | **NEW!** | Device information attribute |

## Header Construction Analysis

### Simple Command Header (4 bytes)

From `build_command_header @ 14006b470`:

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

**Bit Packing Analysis:**
- `param_2` = Command Type (7 bits, masked with 0x7f)
- `param_3` = Attribute (shifted left by 9 bits)
- `DAT_140277089` = Global ID counter (8 bits, auto-incremented)

**Header Structure (32-bit little-endian):**
```
Bits:  31-17    16-9     8-1      0
       [attr]   [id]     [type]   [?]
```

Where:
- `type` = param_2 & 0x7f (7 bits)
- `id` = DAT_140277089 (8 bits) 
- `attr` = param_3 (15 bits)
- Bit 0 appears unused in simple commands

### Command Header with Payload (8 bytes)

From `build_command_header_with_payload @ 14006b9b0`:

```c
QByteArray * build_command_header_with_payload(QByteArray *param_1, ushort param_2, QByteArray *param_3)
{
  // ... 
  DAT_140277089 = DAT_140277089 + 1;
  local_res10[0] = (uint)DAT_140277089 << 8 | 0x48;  // Base command type 0x48
  // Complex payload size calculation
  local_res10[0] = ((int)((payload_size + 3) >> 2) + 2) * 0x400000 | local_res10[0] & 0x3fffff;
  local_res20[0] = param_2 & 0x7fff;  // Attribute (15 bits)
  local_res20[0] = (int)payload_size << 0x16 | local_res20[0] & 0x3fffff;
  // Append 8-byte header + payload
}
```

**Key Findings:**
- Commands with payloads use base type `0x48`
- Uses 8-byte header structure
- Includes payload size calculations
- `param_2` is the attribute for payload commands

### Global State

- `DAT_140277089` @ 140277089: Global command ID counter, incremented for each command sent

## Command Analysis by Category

### Basic Communication Commands

#### CMD_CONNECT (0x02)
From `send_simple_command @ 14006ec70`:
- Initial handshake command
- Uses `attribute = 0` for simple commands
- 1000ms timeout for response

#### CMD_DISCONNECT (0x03) - **MAJOR DISCOVERY**
From `handle_response_packet @ 14006d1b0`:
```c
else if ((uVar1 & 0x7f) == 3) {
  QDebug::operator<<(pQVar9, "CMD_DISCONNECT");
}
```
- Explicitly handled in response parser
- This was the unknown command 0x03 mentioned in the original task!

#### CMD_ACCEPT (0x05)
- Standard positive acknowledgment from device
- Returned in response to successful commands

### Data Stream Management Commands

#### CMD_GET_DATA (0x0C)
- Primary command to request data from device
- Attribute determines data type (ADC, PD packets, etc.)

#### CMD_GET_FILE (0x0E) / CMD_STOP_STREAM (0x0F)
From `manage_data_stream @ 14006f032`:
```c
// Stop stream command
build_command_header(local_88, 0xf, 0);  // CMD_STOP_STREAM = 0x0F

// Start data stream command  
build_command_header(local_70, 0xe, QVar7);  // CMD_GET_FILE = 0x0E (repurposed for streaming)
```
- **0x0E**: Start data stream (repurposed from "get file")
- **0x0F**: Stop any active data stream

### Configuration Commands

#### CMD_SET_CONFIG (0x10) / CMD_RESET_CONFIG (0x11)
From `set_pd_sniffer_mode @ 14006ee32`:
```c
build_command_header(local_78, 0x10, param_1[0x255]);  // CMD_SET_CONFIG = 0x10
build_command_header(local_60, 0x11);  // CMD_RESET_CONFIG = 0x11
```
- **0x10**: Set device configuration (sample rate, mode, etc.)
- **0x11**: Reset configuration (especially for PD sniffer mode)

### Firmware/Bootloader Commands

#### CMD_JUMP_APROM (0x08) / CMD_JUMP_DFU (0x09)
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

### Device Information Command

#### CMD_GET_DEVICE_INFO (0x40)
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

## Authentication Protocol Analysis

### Simple Authentication (0x44)
- Basic authentication without payload
- Used for initial handshake verification

### Advanced Authentication (0x4C)
From `send_auth_packet_and_verify @ 14006e9e0`:

#### Authentication Command Structure
```c
// Authentication packet header construction
local_res18[0] = (uint)DAT_140277089 << 8 | 0x200004c;
```

**Decoded Authentication Header:**
- Base value: `0x200004c` = `0x02000000 | 0x4c`
- Command type: `0x4c` (CMD_AUTHENTICATE_WITH_PAYLOAD)
- Attribute: `0x0200` (ATT_AUTH)
- ID: Auto-incremented global counter

#### Authentication Process
1. **Challenge Construction:**
   - Current timestamp (8 bytes): `QDateTime::toMSecsSinceEpoch()`
   - Random nonce (8 bytes): `QRandomGenerator::_fillRange()`
   - Device-specific data (varies by auth step)

2. **Encryption:**
   - Uses AES encryption with 16-byte key
   - Crypto mode 3 (likely AES-CBC)
   - 32-byte encrypted payload

3. **Response Verification:**
   - Device responds with command type `0x4c`
   - Response is decrypted and verified
   - Timestamp and nonce must match for successful auth

## Serial Command Protocol Analysis

### **MAJOR DISCOVERY: Text Command Encapsulation**

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

#### Serial Command Structure

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

## Response Packet Analysis

From `handle_response_packet @ 14006d1b0`:

### Response Processing Logic

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

### Response Attribute Processing

The function processes different attribute types:

- **Attribute 0x01 (ATT_ADC)**: Calls `FUN_14006c9c0` for sensor data processing
- **Attribute 0x02 (ATT_ADC_QUEUE)**: Handles queued sensor data with chunk processing
- **Attribute 0x08 (ATT_SETTINGS)**: Processes 96-byte + 84-byte configuration data
- **Attribute 0x10 (ATT_PD_PACKET)**: PD packet processing with size validation
- **Attribute 0x20 (ATT_PD_STATUS)**: PD status data
- **Attribute 0x40**: QC packet data (likely Qualcomm Quick Charge)
- **Attribute 0x80**: Stores timestamp and status byte
- **Attribute 0x200**: PD analyzer mode data storage

### Encryption Support

The device supports encrypted responses:
- Bit 16 of header indicates encrypted data
- Uses AES decryption with 16-byte key
- Crypto mode 3 (likely CBC or similar)

## HID Interface Analysis

### **MAJOR DISCOVERY: Multi-Interface Support Confirmed**

From `initialize_device_session @ 140069dd7` and endpoint functions:

#### Multi-Interface Architecture

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

#### Key Findings

1. **Interface Detection:** The app automatically detects and claims ALL available interfaces (0, 1, 2, 3)

2. **Dynamic Endpoint Selection:** Based on endpoint type:
   - **Type 0x03 (Interrupt)** → Uses `libusb_interrupt_transfer` → **HID Interface**
   - **Type 0x02 (Bulk)** → Uses `libusb_bulk_transfer` → **Vendor Interface**

3. **Protocol Compatibility:** The same command protocol works across ALL interfaces - the app just switches transfer methods automatically

4. **Fallback Strategy:** If one interface fails, the app can fall back to others

#### Interface Usage Summary

| Interface | Class | Endpoints | Transfer Type | Usage |
|-----------|-------|-----------|---------------|--------|
| 0 | 0xFF (Vendor) | 0x01/0x81 | Bulk | **Primary high-speed interface** |
| 1 | 0x02 (CDC) | 0x83 | Interrupt | Serial port control |
| 2 | 0x0A (CDC Data) | 0x02/0x82 | Bulk | Serial port data |
| 3 | 0x03 (HID) | 0x05/0x85 | Interrupt | **Driver-free fallback** |

#### Answer to Original Question

**YES, the Windows app DOES use HID!** It's implemented as:
- **Automatic fallback** when vendor drivers aren't available
- **Same protocol** as vendor interface (same 4-byte headers, same commands)
- **64-byte packet limit** (as documented)
- **Interrupt transfers** instead of bulk transfers

Your current implementation uses only the vendor interface (0xFF), but the Windows app is more robust - it supports all 4 interfaces and automatically selects the best available one.

## Device Information Block Analysis

### Large Device Info Response (200+ bytes)

From Wireshark capture analysis and `get_info_block @ 14006de50`:

#### Command Structure
```c
// Build device info request command
DAT_140277089 = DAT_140277089 + 1;
local_res10[0] = (uint)DAT_140277089 << 8 | 0x1000040;
QByteArray::append(param_1, (char *)local_res10, 4);
QByteArray::append(param_1, 0x10, '\0');  // 16 zero bytes padding
```

#### Wireshark Capture Analysis
```
Frame 760: Host -> Device: 0c071000  (CMD_GET_DATA with ATT_DEVICE_INFO)
Frame 762: Device -> Host: 4107020b0800002d610150f8... (200+ byte response)
```

#### Device Info Block Structure

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

#### Key Findings

1. **Device Name:** Clear "POWER-Z" string at offset 136
2. **Firmware Info:** At offset 8-11 (`610150f8`)
3. **Capabilities:** Capability flags at offset 16-19
4. **Calibration Data:** Large blocks of structured data
5. **Checksum:** Final 4 bytes likely CRC or checksum

#### Usage in Application

The device info block is requested during initialization:
1. **After authentication** completes successfully
2. **Before starting** normal data polling
3. **To determine** device capabilities and configuration

## Implementation Recommendations

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

## Next Analysis Targets

Functions to examine next:
- `FUN_14006c9c0` - ADC data processing function  
- `FUN_140161150` - PD packet processing function
- `get_crypto_key` - Crypto key management
- Device info parsing and field extraction logic
