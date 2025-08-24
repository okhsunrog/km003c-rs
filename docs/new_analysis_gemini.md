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
### Step 6: Deeper Dive into PD Packet Request and Processing

My goal is to understand the complete flow of PD data, from request to processing. I will focus on the following:

1.  **PD Data Request:** I will investigate how the `build_command_header` function is used to request PD data, specifically looking for calls with command types `0x10` and `0x11`.
2.  **PD Data Processing:** I will analyze the `handle_response_packet` function to understand how the "inner event stream" is parsed, especially for packets with attributes `0x10`, `0x20`, and `0x40`. I will pay close attention to how the "wrapped" PD messages are handled.
3.  **Full Descriptions:** I will provide detailed descriptions of the functions and data structures involved in this process.

I will now start by investigating the PD data request mechanism.

### Step 7: Analyzing the PD Data Request Mechanism

I have analyzed the `set_pd_sniffer_mode` function (at `0x14006eda0`) and can now describe how the executable requests PD data.

#### The `set_pd_sniffer_mode` function

This function is responsible for both enabling and disabling the PD sniffer mode. It takes a parameter that determines whether to enable or disable the mode.

*   **Enabling PD Sniffer Mode:**
    *   When called with a non-null parameter, the function calls `build_command_header` with command type `0x10` and the parameter value as the attribute.
    *   The command is then sent to the device using the `transceive_data` function.
    *   A timer is started to periodically fetch the PD data.

*   **Disabling PD Sniffer Mode:**
    *   When called with a null parameter, the function calls `build_command_header` with command type `0x11` and an attribute of `0`.
    *   This command is then sent to the device, which likely stops the device from sending PD data.

This confirms that command `0x10` is used to enable PD sniffing with a specific mode (attribute), and command `0x11` is used to disable it.

Now that I understand how the data is requested, I will move on to analyzing how the data is processed, focusing on the "inner event stream" and the "wrapped" PD messages.
### Step 8: Parsing the PD "Inner Event Stream"

I have analyzed the functions responsible for parsing the "inner event stream" contained within the PD data packets. The main parsing function is `FUN_140063a50`, which is called from `handle_response_packet`.

#### The `FUN_140063a50` function

This function is responsible for parsing the entire "inner event stream". It is a large and complex function that is tightly coupled with the UI, but its core logic can be summarized as follows:

1.  **Input:** It takes the raw "inner event stream" as a `QByteArray`.
2.  **Event Type:** It determines the type of event based on the 9th byte of the stream.
3.  **Connection Status:** If the event is a connection status update, it uses a `switch` statement to map the status code to a human-readable string (e.g., "Unattached", "Attached").
4.  **PD Message:** If the 9th byte is `0xAA`, it treats the event as a PD message and proceeds to parse it.
5.  **PD Message Parsing:** The function extracts various fields from the PD message payload, including the message type, port role, and voltage. It uses several helper functions to assist with the parsing.
6.  **UI Update:** Finally, it updates a `QTableWidget` with the parsed information.

#### The `FUN_140063630` helper function

This function is called by `FUN_140063a50` to get a human-readable string for a given PD message type. It works as follows:

1.  **Input:** It takes a `ushort` and a `uint` that represent the message type.
2.  **Message Type Mapping:** It uses the input parameters to look up the message name in a hardcoded array of strings. It can differentiate between control messages, data messages, and custom messages.
3.  **Output:** It returns a `QTableWidgetItem` with its text set to the message name.

Now, I will continue by analyzing the other helper functions to get a complete picture of the parsing logic.
### Step 9: Analyzing the Helper Functions

I have analyzed the helper functions called by `FUN_140063a50` and they provide important insights into the PD message parsing and validation process.

#### The `FUN_140064cc0` function (CRC Calculation)

This function is responsible for calculating an 8-bit CRC (Cyclic Redundancy Check) for a given byte array. It uses a polynomial of `0x29`. This CRC is likely used to verify the integrity of the PD messages.

#### The `FUN_140064bc0` function (Custom Hash/Checksum)

This function calculates a custom hash or checksum for a given byte array. It processes the data in 8-byte chunks and uses a series of additions and bitwise operations to generate the final hash value. This is likely used for a more robust integrity check than the simple CRC.

With the analysis of these helper functions, I now have a comprehensive understanding of how the firmware parses and validates PD messages. The next logical step is to compare this with the existing Rust implementation to ensure its correctness.
### Step 10: Comparison with Rust Implementation and Recommendations

I have compared my findings from the firmware analysis with the existing Rust implementation in `km003c-lib/src/pd.rs`. While the Rust implementation provides a good foundation, there are several key discrepancies that need to be addressed to ensure correctness.

#### Discrepancies

1.  **Event Type Identification:** The most significant discrepancy is in how different event types are identified within the "inner event stream".
    *   **Firmware:** The firmware uses the 9th byte of the stream to identify PD messages (when the value is `0xAA`).
    *   **Rust:** The Rust code uses the first byte of the stream (`0x80-0x9F`) to identify wrapped PD messages. This is incorrect.
    *   **Recommendation:** The `EventPacket::from_slice` function in the Rust code should be updated to use the 9th byte to identify PD messages. The logic for identifying other event types, such as `ConnectionEvent` (`0x45`), should also be verified against the firmware.

2.  **Integrity Checks:** The Rust implementation is missing the integrity checks that are present in the firmware.
    *   **Firmware:** The firmware uses two different functions for integrity checks: `FUN_140064cc0` for an 8-bit CRC and `FUN_140064bc0` for a custom hash/checksum.
    *   **Rust:** The Rust code does not implement these checks.
    *   **Recommendation:** The CRC and custom hash algorithms should be implemented in Rust and integrated into the parsing logic. The `FUN_140064cc0` and `FUN_140064bc0` functions should be carefully translated to Rust.

3.  **PD Message Parsing:** The Rust code relies on the `usbpd` crate for parsing PD messages.
    *   **Firmware:** The firmware has its own custom parsing logic in `FUN_140063a50`.
    *   **Rust:** Using the `usbpd` crate is a good approach, but it's important to ensure that the data passed to it is valid.
    *   **Recommendation:** The custom integrity checks should be performed before passing the data to the `usbpd` crate.

#### Proposed Corrections to `km003c-lib/src/pd.rs`

1.  **Modify `EventPacket::from_slice`:**
    *   The function should be updated to check the 9th byte of the stream for `0xAA` to identify PD messages.
    *   The logic for identifying `ConnectionEvent` and `StatusPacket` should be reviewed and updated to match the firmware's logic.

2.  **Implement Integrity Checks:**
    *   Create a new Rust module (e.g., `integrity.rs`) to house the CRC and custom hash functions.
    *   Translate the logic from `FUN_140064cc0` and `FUN_140064bc0` to Rust.
    *   Call these functions from `EventPacket::from_slice` to verify the integrity of the PD messages before parsing them.

By addressing these discrepancies, the Rust implementation will be much more accurate and reliable. This concludes my analysis of the PD packet processing in the KM003C firmware.
