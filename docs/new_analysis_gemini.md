# Gemini's Analysis of KM003C Firmware

This document details the analysis of the KM003C firmware, with a focus on reverse-engineering the USB Power Delivery (PD) protocol.

## Initial Plan

1.  **Explore the Firmware**: Start by exploring the firmware in Ghidra to identify key functions related to USB communication, command parsing, and data handling.
2.  **Analyze PD Protocol**: Focus on the functions responsible for handling PD data. This includes identifying how PD packets are structured, parsed, and differentiated from other data types like ADC readings.
3.  **Compare with Existing Code**: Compare the findings from the firmware analysis with the current implementation in the `km003c-rs` library.
4.  **Document Discrepancies**: Document any discrepancies found and propose corrections to the Rust code.
5.  **Continuously Update**: This document will be continuously updated with new findings, function analyses, and next steps.

---
## Analysis Log

### Step 1: Initial Exploration

Getting the current program to begin analysis.

### Step 2: Packet Structure Analysis

Based on the decompiled code from Ghidra, I've identified the following key functions and structures:

#### Data Packet Header Structure
The `build_data_packet_header` function (0x14006b9b0) constructs data packet headers for responses with the following structure:

- **First 4 bytes**:
  - Bits 0-7: Packet type (0x48 = 72, indicating data packet)
  - Bits 8-15: Transaction ID (incrementing counter)
  - Bits 16-31: Object count (calculated from payload size)
  
- **Second 4 bytes**:
  - Bits 0-14: Attribute (15 bits, masked with 0x7fff)
  - Bits 15-31: Payload size (shifted by 22 bits)

This matches what was documented in the ghidra.md file.

#### Response Packet Handler
The `handle_response_packet` function (0x14006d1b0) processes incoming data and handles different attribute types:

1. **Attribute 0x01**: ADC data packets (calls `process_adc_packet`)
2. **Attribute 0x02**: ADC data with sample count
3. **Attribute 0x08**: 
4. **Attribute 0x10**: PD sniffer mode data
5. **Attribute 0x20**: PD status data (PdStatus) - This is what we're interested in
6. **Attribute 0x40**: PD data packets (PdPacket)
7. **Attribute 0x80**: 
8. **Attribute 0x200**: 

#### PD Data Handling
From the `handle_response_packet` function, I can see that:

1. For attribute 0x20 (PdStatus), the code logs the hex data but doesn't seem to process it further
2. For attribute 0x40 (PdPacket), the code calls `emit_pd_data_signal` when certain conditions are met
3. For attribute 0x10 (PD sniffer mode), similar processing occurs

#### PD Data Processing
The `on_pd_data_received` function (0x1401585e0) is responsible for emitting signals when PD data is received. It uses Qt's signal/slot mechanism to notify other parts of the application.

The `emit_pd_data_signal` function (0x140161150) emits signals with Qt's meta-object system:
```c
void emit_pd_data_signal(QObject *param_1,undefined8 param_2)
{
  void *local_18;
  undefined8 local_10;
  
  local_18 = (void *)0x0;
  local_10 = param_2;
  QMetaObject::activate(param_1,(QMetaObject *)&DAT_14022d610,0xd,&local_18);
  return;
}
```

#### ADC vs PD Processing
The `process_adc_packet` function (0x14006c9c0) handles ADC data processing, which involves:
1. Reading raw ADC values from the packet
2. Converting them to voltage/current readings
3. Updating internal data structures and UI elements

This suggests that PD processing likely follows a similar pattern but for PD-specific data.

### Step 3: Key Findings About PD Data

1. **PD Status Data (Attribute 0x20)**:
   - Currently only logged as hex data
   - Not processed for actual PD events
   - This matches the user's observation that PdStatus packets were previously ignored

2. **PD Packet Data (Attribute 0x40)**:
   - Processed by emitting signals to other parts of the application
   - Likely contains the actual PD messages

3. **PD Sniffer Mode (Attribute 0x10)**:
   - Also processes PD data, but in sniffer mode

### Step 4: Deep Dive Into PD Data Processing

Based on my analysis of the firmware:

1. **PD Data Flow**:
   - PD data arrives as `PutData` packets with specific attributes
   - `handle_response_packet` identifies PD data by attribute (0x20 for PdStatus, 0x40 for PdPacket)
   - For attribute 0x40, the data is extracted and `emit_pd_data_signal` is called
   - The emitted signal uses Qt's meta-object system to notify connected slots

2. **Inner Event Stream Structure**:
   - The firmware treats PD data as an "inner event stream" within the payload
   - This is consistent with the Rust library's implementation
   - The stream contains concatenated PD events similar to what the Rust code parses

3. **Missing Processing in Firmware**:
   - For attribute 0x20 (PdStatus), the firmware only logs the data as hex but doesn't process it
   - This explains why the user couldn't correctly parse PD data - they were likely receiving PdStatus packets that the firmware itself wasn't fully processing

### Step 5: Comparison with Rust Implementation

Looking at the current Rust implementation in `km003c-lib/src/pd.rs`:

1. **EventPacket Types**:
   - **ConnectionEvent**: Identified by a first byte of `0x45`, 6 bytes long
   - **StatusPacket**: Default packet type for unknown identifiers, 12 bytes long
   - **WrappedPdMessage**: PD messages wrapped in a 6-byte header, followed by standard PD message

2. **Parsing Logic**:
   - Correctly handles the ambiguity between StatusPacket and WrappedPdMessage for bytes in the 0x80-0x9F range
   - Uses the `usbpd` crate to validate and parse PD messages
   - Falls back to StatusPacket if PD message parsing fails

3. **Discrepancies**:
   - The firmware seems to use attribute 0x20 for PD status data, which the Rust code was ignoring
   - The Rust implementation correctly identifies that PdStatus packets contain valuable information in the "inner event stream"
   - Need to verify if the 0x45 byte pattern and other parsing rules match what's in the firmware

### Next Steps

1. **Examine the actual payload data structures**:
   - Look how the firmware processes the data after `emit_pd_data_signal`
   - Check if there are functions that parse the "inner event stream" format
   - Understand how PdStatus (0x20) differs from PdPacket (0x40) in content

2. **Look for database storage functions**:
   - Find how PD data is stored in SQLite tables
   - Examine the table structures for `pd_table` and `pd_chart`
   - Understand how the firmware maps the inner event stream to database rows

3. **Verify magic byte patterns**:
   - Confirm if 0x45 is indeed used for connection events in the firmware
   - Check if bytes in the 0x80-0x9F range are used for PD messages
   - Identify any other packet types in the inner stream

4. **Update the Rust implementation**:
   - Ensure PdStatus (0x20) packets are properly processed
   - Verify that the inner event stream parsing matches what the firmware does
   - Check if timestamp formats and other structures are consistent

### Functions to Further Analyze

1. Functions that process the data after `emit_pd_data_signal` is called
2. Database storage functions for PD data
3. Memory structures that store parsed PD events
4. Functions that parse the "inner event stream" format