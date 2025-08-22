# KM003C Protocol Analysis from Ghidra

This document contains the findings from analyzing the KM003C proprietary executable (`Mtools.exe`) using Ghidra reverse engineering tools. The analysis reveals the internal packet structure and data handling mechanisms.

## Key Functions Discovered

### Packet Construction Functions

#### `build_command_header` (0x14006b470)
**Purpose**: Builds control packet headers for commands
**Signature**: `QByteArray* build_command_header(QByteArray* output, unsigned char command_type, unsigned char attribute)`

**Implementation Details**:
```c
local_res10[0] = ((uint)param_3 << 9 | (uint)DAT_140277089) << 8 | param_2 & 0x7f;
```

**Packet Structure**:
- **Bytes 0-3**: 32-bit header
  - Bits 0-6: Command type (7 bits, masked with 0x7f)
  - Bits 7-15: Transaction ID (auto-incrementing from global variable)
  - Bits 16-24: Attribute (shifted by 9 bits)
  - Bits 25-31: Reserved/unused

**Command Types Identified**:
- `0x0c` (12): GetData - Request data from device
- `0x0e` (14): GetData with specific attribute
- `0x0f` (15): GetData for data stream management
- `0x10` (16): Set PD sniffer mode
- `0x11` (17): Get PD data

#### `build_data_packet_header` (0x14006b9b0)
**Purpose**: Builds data packet headers for responses
**Signature**: `QByteArray* build_data_packet_header(QByteArray* output, unsigned short attribute, QByteArray* payload)`

**Implementation Details**:
```c
local_res10[0] = (uint)DAT_140277089 << 8 | 0x48;
local_res10[0] = ((int)((longlong)(_Var1 + (ulonglong)((uint)(_Var1 >> 0x3f) & 3)) >> 2) + 2) * 0x400000 | local_res10[0] & 0x3fffff;
local_res20[0] = param_2 & 0x7fff;
local_res20[0] = (int)_Var1 << 0x16 | local_res20[0] & 0x3fffff;
```

**Packet Structure**:
- **First 4 bytes** (`local_res10`):
  - Bits 0-7: Packet type (0x48 = 72, indicating data packet)
  - Bits 8-15: Transaction ID
  - Bits 16-31: Object count (calculated from payload size)
- **Second 4 bytes** (`local_res20`):
  - Bits 0-14: Attribute (15 bits, masked with 0x7fff)
  - Bits 15-31: Payload size (shifted by 22 bits)

### Packet Processing Functions

#### `handle_response_packet` (0x14006d1b0)
**Purpose**: Main packet response handler that processes incoming data
**Signature**: `long long handle_response_packet(long long device_context, unsigned short attribute)`

**Key Processing Logic**:
1. **Packet Type Check**: Verifies response is type 0x41 (PutData)

---

## CC/PD Attach-Detach Event Parsing

### Event Parser – "Parse PD/CC Connection Events" (0x140063a50)
- **Function**: `void FUN_140063a50(QTableWidget *table, QByteArray *raw, QString *out)`
- **Purpose**: Parses incoming buffer for CC/PD attach/detach events, maps to state/UI strings
- **Event mapping logic:**
  - Raw bytes parsed:
    - Index 8: Event type/state
    - Index 9-10: Encodes type (bits: port roles, cable/source/sink/etc)
    - Index 11+: Subtypes for PD/CC change events
    - Index 0xc/12: Additional length or info
  - State table (switch): 0=Disabled, 1=ErrorRecovery, 2=Unattached, 3=Attach Wait, 4=Attached, etc. More mapped in switch
  - Presents "Unattached", "Attach Wait", "Attached" etc with coloring/indicator in UI
- **Attachment or Detachment trigger**:
  - Attach: When state moves to "Attach Wait" or "Attached"
  - Detach: When moves to "Unattached" or Error/Disabled
- **Calls:**
  - Downstream calls update another widget/table for display
  - Handles PD state (PD extended logic at lines with object count/attributes)
  - Related: 0x140059920 (calls this for event receive), 0x14005a070 (dispatches multiple events)

### Key Strings Mapped (from binary):
- "Unattached", "Attach Wait", "Attached", "Attach Wait Monitor", "ErrorRecovery", "Disabled"
- "CC1:2.40V", "CC2:2.40V" (state shown in UI, possibly voltage thresholds for attach)

### Supporting Functions
- 0x140059920 — Receives/buffers events, calls parser above
- 0x14005a070 — Event dispatcher, processes batches or multiple events, calls state/event parser (above)

### Notes on Attach/Detach Logic
- Attach detected by event/state in byte stream, switch/case logic in 0x140063a50
- Detach is similarly mapped in state table
- Exact state triggers:
  - Attached: state==4 (parsed from byte/bit field)
  - Attach wait: state==3
  - Unattached: state==2
- Other fields: further struct or inline logic parses PD-specific fields (e.g. parsing roles, port types, Vbus/CC states)

---

## Names/Comments Added from Ghidra Analysis
- 0x140063a50: "Parse PD/CC attachment/detachment event, set state for table UI, maps raw bytes to human-readable CC/PD connection info."
- 0x140024870: "Sets up meter/CC1-CC2/DM/DP widgets—static text layout for UI, not parsing events or PD."
- 0x140059920: "Calls PD/CC attach-detach event parser (0x140063a50), likely receives or buffers PD/CC connection events."
- 0x14005a070: "Receives and processes multiple PD/CC events, calls event/state parser (0x140063a50), probably main event dispatcher for PD attach/detach."

---

**TODO**: continue annotation and variable renaming for all event/PD parsing logic found for km003c protocol, cross-reference packet parsing with UI state updates for 100% coverage.
