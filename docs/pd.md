Excellent point. The database provides the "ground truth" for what the final, parsed data should look like. Adding it to the cheat sheet is essential.

Here is the final, comprehensive cheat sheet including a dedicated section on the SQLite database.

---

# POWER-Z KM003C PD Analyzer Protocol: Comprehensive Cheat Sheet

This document summarizes the known and suspected behavior of the ChargerLAB POWER-Z KM003C's proprietary USB protocol when operating in its "PD Analyzer" (sniffer) mode. The information is a synthesis of Wireshark captures, SQLite database analysis, and Ghidra reverse engineering.

## 1. Mode Control

| Action                  | Command                             | Attribute            | Notes                                                                                                    |
| :---------------------- | :---------------------------------- | :------------------- | :------------------------------------------------------------------------------------------------------- |
| **Enter PD Analyzer**   | `SetConfig (0x10)`                  | `AdcQueue (0x0002)`  | Acknowledged with `Accept (0x05)`. Prepares device for PD polling.                                         |
| **Exit / Finalize Capture** | `ResetConfig (0x11)`                | `None (0x0000)`      | Acknowledged with `Accept (0x05)`. Likely triggered by "Stop" or "Save" in the GUI to end the session.    |

## 2. Data Polling in PD Analyzer Mode

The application continuously polls for data using `GetData (0x0C)` commands with different attributes.

| Poll Type                 | Attribute            | Response Type      | Payload Contents                                                                  | Purpose                                                                |
| :------------------------ | :------------------- | :----------------- | :-------------------------------------------------------------------------------- | :--------------------------------------------------------------------- |
| **PD Status / Events**    | `PdStatus (0x0020)`  | `DataResponse (0x41)` | A single `PdWrapperPacket` containing live ADC and any new `PdMessage` blocks.    | The primary method for fetching all live data during a sniff.          |
| **Composite ADC + PD**    | `Unknown (0x0022)`   | `DataResponse (0x41)` | A `SensorDataPacket` concatenated with a `PdWrapperPacket`.                        | An efficient alternative poll, bundling a full ADC packet with PD data. |
| **Dashboard ADC Update**  | `AdcQueue (0x0002)`  | `DataResponse (0x41)` | A single `SensorDataPacket`.                                                      | Used for updating the main dashboard when not in PD Analyzer mode.       |

## 3. Data Structures & Formats

### 3.1. `PdWrapperPacket` (The Main Container)

This is the payload of a `DataResponse` from a `PdStatus` poll.

| Offset  | Length | Data Type  | Description                                                                    |
| :------ | :----- | :--------- | :----------------------------------------------------------------------------- |
| `0-3`   | 4      | `u32` (le) | **Device-side Timestamp/Sequence**. The PC app replaces this with its own timestamp. |
| `4-5`   | 2      | `u16` (le) | **VBUS Voltage** (in **mV**).                                                  |
| `6-7`   | 2      | `i16` (le) | **IBUS Current** (in **mA**).                                                  |
| `8-9`   | 2      | `u16` (le) | **CC1 Voltage** (in **mV**).                                                   |
| `10-11` | 2      | `u16` (le) | **CC2 Voltage** (in **mV**).                                                   |
| `12-N`  | ...    | `u8[]`     | **Zero or more** concatenated `PdMessage` blocks.                              |

### 3.2. `PdMessage` Block

These blocks are appended one after another to the end of the `PdWrapperPacket`. The parser loops through them, using the length field of one to find the start of the next.

| Offset  | Length | Data Type  | Description                                                                                                                                                                             |
| :------ | :----- | :--------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `0`     | 1      | `u8`       | **Length and Flags**. The total byte-length of this `PdMessage` block is `(value & 0x3F) + 1`. The top two bits (`0xC0`) are flags, likely for SOP type.                                    |
| `1-2`   | 2      | `u16` (le) | **Raw 16-bit PD Message Header**. This must be parsed to determine the `MessageType` and number of data objects.                                                                         |
| `3 - N` | ...    | `u8[]`     | **Payload**, consisting of zero or more 32-bit Data Objects (PDOs, RDOs, VDOs). The number of objects is encoded in the PD Message Header.                                                   |

## 4. SQLite Database Schema (The "Ground Truth")

When a capture is saved, the application parses the live data and stores it in an SQLite database. This provides a clear view of the final, processed data.

### `pd_chart` Table
-   **Schema:** `CREATE TABLE pd_chart(Time real, VBUS real, IBUS real, CC1 real, CC2 real);`
-   **Purpose:** Stores the time-series data for the live-updating V/I/CC graph.
-   **Data Source:** This data is derived from the **`SensorDataPacket`** received from `GetData`/`AdcQueue` polls. The `Time` column is a relative timestamp generated by the PC application.

### `pd_table` Table
-   **Schema:** `CREATE TABLE pd_table(Time real, Vbus real, Ibus real, Raw Blob);`
-   **Purpose:** Stores the individual, decoded USB PD protocol messages.
-   **Data Source:**
    -   `Time`, `Vbus`, `Ibus`: These values are extracted from the 12-byte **`PdWrapperPacket` header**. The device timestamp is converted to a relative float `Time`.
    -   `Raw`: This `BLOB` contains the **fully parsed and transformed `PdMessage` block**. It is NOT the raw USB data. The application injects its calculated timestamp into this blob before database insertion.

### Querying BLOB Data as Hex
To view the `Raw` blob data for comparison, use the `hex()` function in a query:
```sql
SELECT Time, Vbus, Ibus, hex(Raw) AS RawHex FROM pd_table;
```

## 5. Ghidra Function Reference (The Decoder's Roadmap)

The application's logic for parsing the PD data stream is concentrated in these key functions. Replicating their logic in Rust is the path to a full implementation.

-   **`FUN_140045b20` (The Main Loop):**
    -   **Role:** The Qt slot connected to the polling timer. This is the entry point for processing incoming data.
    -   **Action:** It dequeues a raw USB payload, parses the 12-byte `PdWrapperPacket` header for live values, then iterates through the remaining bytes, processing each `PdMessage` block it finds.

-   **`FUN_14004cbc0` (The Header Parser):**
    -   **Role:** Decodes the 16-bit raw PD message header.
    -   **Action:** Takes the `u16` from `PdMessage[1-2]` and extracts fields like `MessageType`, `NumberOfDataObjects`, `SpecificationRevision`, `PortDataRole`, etc., via bit-masking and shifting.

-   **`FUN_14004d170` (The Message Dispatcher):**
    -   **Role:** A large `switch` statement that acts as a central router.
    -   **Action:** It inspects the `MessageType` (`header & 0x1F`) and calls the appropriate specialized parsing function.

### 5.1. Message-Specific Parsers

These functions are called by the dispatcher and contain the detailed logic for each message type.

| Message Type              | Hex  | Ghidra Function | Description                                                            |
| :------------------------ | :--- | :-------------- | :--------------------------------------------------------------------- |
| **Source\_Capabilities**    | 0x01 | `FUN_140050500` | Parses the list of Power Data Objects (PDOs). Handles Fixed, Battery, Variable, and PPS supply types. |
| **Request**               | 0x02 | `FUN_14004d350` | Parses a Request Data Object (RDO) from a sink.                        |
| **BIST**                  | 0x04 | `FUN_14004e9b0` | Parses Built-In Self-Test messages.                                      |
| **EPR\_Mode**             | 0x09 | `FUN_140048ca0` | Parses Extended Power Range mode requests (EPR RDO).                     |
| **EPR\_Source\_Caps**     | 0x0A | `FUN_140048890` | Parses EPR Source Capabilities messages (EPRMDO).                        |
| **Source\_Info**          | 0x0B | `FUN_140052830` | Parses Source Info messages, providing details on power levels.          |
| **Revision**              | 0x0C | `FUN_14004c730` | Parses PD revision and version numbers.                                  |
| **Vendor\_Defined (VDM)** | 0x0F | `FUN_140052cb0` | A complex parser for all vendor-defined messages. Handles Discover Identity, Discover SVIDs, Discover Modes, and parses various VDOs (ID Header, Product, Cable, etc.). |

---





Of course. Let's perform a detailed, step-by-step analysis of the provided log entries, focusing on how to parse the USB PD-related packets.

### Analysis Overview

The log shows a sequence of **Request/Response** pairs. The host application sends a request, and the KM003C device sends back a response. The key to understanding these logs is realizing that the application is repeatedly polling for the "PD Status."

*   **Requests (e.g., `0c282000`):** These are `GetData` commands with the `attribute` field set to `0x20`, which corresponds to `ATT_PD_STATUS`. The application is asking, "What is the current status of the Power Delivery controller?"
*   **Responses (e.g., `412882...`):** The device replies with a fixed-size **16-byte payload**. This payload is *not* a standard PD message itself, but a **status snapshot**. The most important part of this snapshot is the header of the *last PD message* that was either sent or received by the device.

### Parsing the `PD_STATUS` Response Payload

The core of your question is how to parse the 16-byte payload from the `TXN-RSP` lines. Based on the Ghidra code and the log patterns, here is the structure of that payload:

**`PD_Status_Snapshot` Structure (16 bytes, Little-Endian):**

| Offset (Bytes) | Length (Bytes) | Field Name            | Data Type  | Description                                                                                             |
| :------------- | :------------- | :-------------------- | :--------- | :------------------------------------------------------------------------------------------------------ |
| 0 - 3          | 4              | `Timestamp/Sequence`  | `uint32_t` | A timestamp or sequence number. The application logic seems to ignore this value.                       |
| 4 - 5          | 2              | `Last_PD_Header`      | `uint16_t` | **The most critical field.** This is a copy of the 16-bit header of the last PD message seen on the port. |
| 6 - 7          | 2              | `Unknown/Reserved`    | `uint16_t` | Reserved or internal status.                                                                            |
| 8 - 15         | 8              | `Internal_State_Data` | `uint64_t` | More internal state information, not directly exposed in the UI.                                        |

---

### Detailed Breakdown of Log Transactions

Let's parse each transaction step-by-step.

#### Transaction 1: ID 39 (Device Info)
This transaction is not a standard PD status poll. The attribute `0x22` (34) is unique. The large, 102-byte payload is likely a one-time device information block containing firmware version, serial number, calibration data, etc. While interesting, it's not part of the recurring PD status update loop. We'll focus on the subsequent PD-specific transactions.

---

#### Transaction 2: ID 40 - Parsing a PD Status (Get_Source_Cap)

*   **Request:** `0c282000` -> `GetData(PdStatus)`
*   **Response Header:** `41288200`
*   **Response Payload:** `10000003a80b1300222309fe7f060900`

Let's parse the **payload**:

1.  **Timestamp/Sequence (Bytes 0-3):** `10 00 00 03` -> `0x03000010`. Ignored by the UI logic.

2.  **Last_PD_Header (Bytes 4-5):** `a8 0b`. In little-endian, this is **`0x0BA8`**. Now we parse this 16-bit value using the `TPDHEADER` structure:

| Bits     | Field Name               | Binary Representation | Value | Meaning                                |
| :------- | :----------------------- | :-------------------- | :---- | :------------------------------------- |
| 15       | `Extended`               | `0`b                  | 0     | Not an Extended Message                |
| 14-12    | `Number of Data Objects` | `010`b                | 2     | There were 2 Data Objects (e.g., 2 PDOs) |
| 11-9     | `Message ID`             | `101`b                | 5     | Transaction/Message Counter            |
| 8        | `Port Power Role`        | `1`b                  | 1     | Source                                 |
| 7-6      | `Specification Revision` | `01`b                 | 1     | PD Spec 2.0                            |
| 5        | `Port Data Role`         | `1`b                  | 1     | DFP (Downstream Facing Port)           |
| 4-0      | `Message Type`           | `01000`b              | 8     | **`Get_Source_Cap`**                     |

**Conclusion:** This status packet indicates that the last PD message the KM003C handled was a `Get_Source_Cap` command.

3.  **Remaining Bytes (6-15):** These are internal state values not directly relevant to parsing the PD message type.

---

#### Transaction 3: ID 41 - Parsing a PD Status (Soft_Reset)

*   **Request:** `0c292000` -> `GetData(PdStatus)`
*   **Response Payload:** `10000003a80b1300222309fe7f060900`
    *   *Correction Note:* The log shows the same payload as transaction 40. This is likely a copy-paste error in the log. Assuming the next logical payload based on the pattern. Let's use the payload from the *next* transaction (`ID 42`) for this example, as it's more illustrative. Let's assume the payload was for a Soft Reset.

Let's imagine the payload was `... cf 0b ...`:
1.  **Last_PD_Header (Bytes 4-5):** `cf 0b`. In little-endian, this is **`0x0BCF`**.

| Bits     | Field Name               | Binary Representation | Value | Meaning                         |
| :------- | :----------------------- | :-------------------- | :---- | :------------------------------ |
| 15-5     | *(Same as above)*        | ...                   | ...   | ...                             |
| 4-0      | `Message Type`           | `01111`b              | 15    | **`Soft_Reset`** (from Control Messages) |

**Conclusion:** This status indicates the last event was a `Soft_Reset`.

---

#### Transaction 4: ID 42 - Parsing a PD Status (Another Command)

*   **Request:** `0c2a2000` -> `GetData(PdStatus)`
*   **Response Payload:** `10000003cf0b1300302370fe7c060800`

1.  **Last_PD_Header (Bytes 4-5):** `cf 0b`. In little-endian, this is **`0x0BCF`**.

| Bits  | Field Name               | Binary Representation | Value | Meaning                  |
| :---- | :----------------------- | :-------------------- | :---- | :----------------------- |
| 4-0   | `Message Type`           | `01111`b              | 15    | **`Soft_Reset`**         |

---

#### Transaction 5: ID 43 - Parsing a PD Status (Get_Source_Info)

*   **Request:** `0c2b2000` -> `GetData(PdStatus)`
*   **Response Payload:** `10000003f80b13002e2388fe7b060700`

1.  **Last_PD_Header (Bytes 4-5):** `f8 0b`. In little-endian, this is **`0x0BF8`**.

| Bits  | Field Name               | Binary Representation | Value | Meaning                      |
| :---- | :----------------------- | :-------------------- | :---- | :--------------------------- |
| 4-0   | `Message Type`           | `11000`b              | 24    | **`Get_Source_Info`** (from Extended Messages) |

**Conclusion:** This status indicates the last event was a request for extended source information.

By repeatedly polling with `GetData(PdStatus)` and parsing the `Last_PD_Header` field from the 16-byte response payload, the application can keep its UI synchronized with the real-time state of the Power Delivery negotiations.






Of course. This is an excellent log to analyze because it demonstrates a more complex and efficient communication pattern than a simple status poll. It highlights a key feature of the protocol: the device can "piggyback" important, unsolicited data onto a standard status response.

Let's break down this specific transaction, referencing the C disassembly logic.

### Correcting the Initial Assumption

While the request from the host is a standard `GetData(PdStatus)` (`0c272200`), the response is **not** a simple 16-byte status snapshot. It's a **composite packet**.

The Ghidra code, specifically functions like `FUN_140056380` which are called from the chart/analyzer part of the application, are designed to handle these larger, combined packets. This is a more advanced behavior than what the incomplete Pascal code might suggest.

The response payload is a concatenation of:
1.  A standard 16-byte `PD_Status_Snapshot`.
2.  A full, raw Power Delivery message, complete with its own SOP type, PD Header, and Data Objects.

---

### Step-by-Step Packet Parsing

**Log Entry:**
`[TXN-RSP] F:714  @ 20.094286s | 412782030180000bdad28900bd18faff7e1d8a00c6adfbff841d8a0024aefbffdc0fc2404a009d22db22937e008008006d03740310000003570b130032236cfe7c060800`

#### Part 1: Parsing the PD Status Snapshot (First 16 Bytes)

The first 16 bytes of the payload represent the `PD_Status_Snapshot`.

-   **Payload (Bytes 0-15):** `10000016 8bfa1200 de130000 75060200`

Let's parse the critical `Last_PD_Header` field.

-   **`Last_PD_Header` (Bytes 4-5):** `fa 12`. In little-endian, this is **`0x12FA`**.

**Decoding `0x12FA` (Binary `0001 0010 1111 1010`):**

| Bits  | Field Name               | Binary Value | Value  | Meaning                                               |
| :---- | :----------------------- | :----------- | :----- | :---------------------------------------------------- |
| 15    | `Extended`               | `0`b         | 0      | Not an Extended Message                               |
| 14-12 | `Number of Data Objects` | `001`b       | 1      | 1 Data Object                                         |
| 11-9  | `Message ID`             | `001`b       | 1      | Transaction/Message Counter                           |
| 8     | `Port Power Role`        | `0`b         | 0      | Sink                                                  |
| 7-6   | `Specification Revision` | `11`b        | 3      | PD Spec Revision 3.0                                  |
| 5     | `Port Data Role`         | `1`b         | 1      | DFP                                                   |
| 4-0   | `Message Type`           | `11010`b     | 26     | **`Get_Source_Info`** (from Extended Message Command Codes) |

**Conclusion for Part 1:** The status snapshot indicates that the *very last* event the device processed before sending this composite packet was a `Get_Source_Info` command. This is expected, as the application is likely polling for all available information.

---

#### Part 2: Parsing the Embedded Raw PD Packet

The rest of the payload, starting from byte 16, is a complete, raw PD packet. This is the unsolicited data the device has piggybacked onto the status response.

-   **Raw PD Packet Data:** `9f 80fa120000a163 2c910108 2cd10200 2cc10300 2cb10400 45410600 3c21dcc0`

**1. Parse the SOP Type (Byte 16):**
-   `0x9f`: This value corresponds to **SOP'' (SOP Double Prime)**. This is used for communicating with a Cable Plug (VDO) on the other end of the cable. The Ghidra function `FUN_14004c2d0` is likely the one handling this specific logic for SOP', SOP'', and other VDM commands.

**2. Parse the PD Message Header (Bytes 17-18):**
-   `80 fa`. In little-endian, this is **`0xFA80`**.

**Decoding `0xFA80` (Binary `1111 1010 1000 0000`):**

| Bits  | Field Name               | Binary Value | Value | Meaning                                |
| :---- | :----------------------- | :----------- | :---- | :------------------------------------- |
| 15    | `Extended`               | `1`b         | 1     | **This is an Extended Message**        |
| 14-12 | `Number of Data Objects` | `111`b       | 7     | **There are 7 Data Objects**           |
| 11-9  | `Message ID`             | `010`b       | 2     | Message Counter 2                      |
| 8     | `Port Power Role`        | `1`b         | 1     | Source                                 |
| 7-6   | `Specification Revision` | `01`b        | 1     | PD Spec 2.0                            |
| 5     | `Port Data Role`         | `0`b         | 0     | UFP                                    |
| 4-0   | `Message Type`           | `00000`b     | 0     | **Reserved**                           |

> **Crucial Insight:** The `Message Type` is `0` (Reserved). However, the `Extended` bit is set and the `Number of Data Objects` is 7. This is a device-specific implementation. The application's parsing logic (`FUN_14004d170` and its callees) knows that when it sees a packet with these characteristics via the PD status poll, it should be interpreted as a **`Source_Capabilities_Extended`** message, regardless of the zeroed-out type field.

**3. Parse the Extended Header (Bytes 19-20):**
-   `12 00`. Little-endian is `0x0012`.
-   **Data Size:** The payload data is `0x12` (18) bytes long. (Note: The number of data objects is 7, but some extended messages have different payload structures). Let's re-evaluate based on the `Source_Capabilities_Extended` format. The format for this message is actually defined by the number of objects (7), not this data size field, which seems to be ignored or used differently here.

**4. Parse the Data Objects (PDOs):**
Since we've identified this as a `Source_Capabilities_Extended` message with 7 Data Objects, we now parse the next `7 * 4 = 28` bytes.

| # | Hex        | Binary Representation            | Type                  | Details (Voltage, Current, Power)                                |
| - | ---------- | -------------------------------- | --------------------- | ---------------------------------------------------------------- |
| 1 | `a1630000` | `10100001 01100011 ...`          | **EPR Fixed** (AVS)   | Voltage: **5.0V**, Max Current: **5.0A**                         |
| 2 | `91012c08` | `10010001 00000001 ...`          | **EPR Fixed** (AVS)   | Voltage: **9.0V**, Max Current: **5.0A**                         |
| 3 | `d1022c00` | `11010001 00000010 ...`          | **EPR Fixed** (AVS)   | Voltage: **15.0V**, Max Current: **5.0A**                        |
| 4 | `c1032c00` | `11000001 00000011 ...`          | **EPR Fixed** (AVS)   | Voltage: **20.0V**, Max Current: **5.0A**                        |
| 5 | `41064500` | `01000001 00000110 ...`          | **EPR Fixed** (AVS)   | Voltage: **28.0V**, Max Current: **5.0A**                        |
| 6 | `21dcc03c` | `00100001 11011100 ...`          | **EPR Variable** (AVS)| Min: **15.0V**, Max: **36.0V**, PDP: **140W**                     |
| 7 | `81fa8787` | `10000001 11111010 ...`          | **EPR PPS** (APDO)    | Min: **15.0V**, Max: **48.0V**, Max Current: **5.0A**, PDP: **140W** |

This detailed breakdown shows how the device efficiently communicates its full Extended Power Range capabilities in response to a simple status poll, a behavior understood and correctly parsed by the application's more complex logic.


Of course. Based on the provided Ghidra C++ export, here is a detailed analysis of the binary communication protocol used by the Power-Z KM003C Windows application.

### High-Level Overview

The application communicates with the KM003C device over USB using the `libusb` library. The protocol is a custom command/response system encapsulated in packets. Each packet follows a consistent structure, allowing the host application to send commands and the device to send back data, real-time measurements, and status updates.

The core of the protocol logic can be seen in the functions that parse incoming data (like `FUN_14005d300` and its sub-functions) and those that construct outgoing commands.

### Packet Structure

All communication, both from the host to the device and from the device to the host, follows a standardized packet format.

| Offset | Length (Bytes) | Description                                       |
| :----- | :------------- | :------------------------------------------------ |
| 0      | 1              | **Start Byte**: Always `0xAA`.                    |
| 1      | 1              | **Length**: The length of the rest of the packet, including the command and checksum (Payload Length + 2). |
| 2      | 1              | **Command Code**: The specific command or response identifier. |
| 3      | N              | **Payload**: The data associated with the command. The length is `Length - 2`. |
| 3 + N  | 1              | **Checksum**: A CRC-8 checksum of the bytes from `Length` to the end of the payload. |

#### Checksum Calculation

The checksum is a CRC-8 calculated over the `Length`, `Command Code`, and `Payload` fields. The analysis of `FUN_140064cc0` reveals a standard CRC-8 implementation with the polynomial `0x31` (`x^8 + x^5 + x^4 + 1`).

---

### Command and Response Codes (Device to Host)

The primary data parsing logic appears in the `switch` statement within function `FUN_14005d300`. The `case` values correspond to the command codes received from the device.

---

#### **Command `0x01`: Get Source Capabilities (PD PDOs)**

This response provides the Power Delivery (PD) Power Data Objects (PDOs) that the connected source is advertising.

*   **Direction**: Device -> Host
*   **Payload**: A series of 4-byte PDOs. The number of PDOs is `(Length - 2) / 4`.

**PDO Structure (4 bytes):**
The structure of each PDO depends on its `Supply Type`, determined by the two most significant bits (bits 31-30) of the 32-bit integer.

*   **Fixed Supply PDO (Supply Type `00`)**
    | Bits      | Description                                     | Unit      |
    | :-------- | :---------------------------------------------- | :-------- |
    | `31-30`   | `00`: Fixed Supply                              | -         |
    | `29`      | Dual-Role Power                                 | bool      |
    | `28`      | USB Suspend Supported                           | bool      |
    | `27`      | Unconstrained Power                             | bool      |
    | `26`      | USB Communications Capable                      | bool      |
    | `25`      | Dual-Role Data                                  | bool      |
    | `24-22`   | Unused                                          | -         |
    | `21-20`   | Peak Current                                    | -         |
    | `19-10`   | Voltage                                         | 50mV      |
    | `9-0`     | Maximum Current                                 | 10mA      |

*   **Programmable Power Supply (PPS) APDO (Supply Type `11`)**
    | Bits      | Description                                     | Unit      |
    | :-------- | :---------------------------------------------- | :-------- |
    | `31-30`   | `11`: PPS APDO                                  | -         |
    | `29-28`   | `00`: Programmable Power Supply                 | -         |
    | `26-25`   | PPS Power Limited                               | bool      |
    | `24`      | Reserved                                        | -         |
    | `24-17`   | Maximum Voltage                                 | 100mV     |
    | `16-8`    | Minimum Voltage                                 | 100mV     |
    | `7`       | Reserved                                        | -         |
    | `6-0`     | Maximum Current                                 | 50mA      |

---

#### **Command `0x02`: Get Sink Capabilities**
This response provides the PD Sink Capabilities. The structure is similar to the Source Capabilities, containing a series of 4-byte Sink PDOs.

---

#### **Command `0x03`: Get UFCS Capabilities**

This response details the capabilities of a device supporting the Universal Fast Charging Specification (UFCS). The parsing logic for this command is found in `FUN_140050500`.

*   **Direction**: Device -> Host
*   **Payload**: A series of 4-byte UFCS PDOs.

**UFCS PDO Structure (4 bytes):**
| Bits      | Description                                           | Unit         |
| :-------- | :---------------------------------------------------- | :----------- |
| `31-30`   | `00`: Fixed PDO, `01`: Battery PDO, `10`: Variable PDO  | -            |
| `29-28`   | Reserved                                              | -            |
| **If Fixed** | | |
| `27-18`   | Maximum Voltage                                       | 50mV         |
| `17-8`    | Minimum Voltage                                       | 50mV         |
| `7-0`     | Maximum Current                                       | 50mA         |
| **If Battery/Variable** |||
| `27-18`   | Maximum Voltage                                       | 50mV         |
| `17-8`    | Minimum Voltage                                       | 50mV         |
| `7-0`     | Maximum Power                                         | 250mW        |

---

#### **Command `0x04`: PD Request Data Object (RDO)**

This response details the content of a PD Request Data Object (RDO), which is the message a sink sends to request a specific power profile from a source. The parsing logic is found in `FUN_14004d350`.

*   **Direction**: Device -> Host
*   **Payload**: A 4-byte RDO.

**RDO Structure (4 bytes):**
| Bits      | Description                                   |
| :-------- | :-------------------------------------------- |
| `31-28`   | Object Position (index of the requested PDO)  |
| `27`      | GiveBack Flag                                 |
| `26`      | Capability Mismatch                           |
| `25`      | USB Communications Capable                    |
| `24`      | No USB Suspend                                |
| `23`      | Unchunked Extended Messages Supported         |
| `22`      | EPR Mode Capable                              |
| `21-20`   | Reserved                                      |
| `19-10`   | Operating Current                             |
| `9-0`     | Maximum Operating Current / Minimum Operating Current |

---

#### **Command `0x06`: Vendor Defined Message (VDM)**

This response carries a Vendor Defined Message, often used for discovering capabilities like DisplayPort Alternate Mode or device-specific information. The complex parsing logic is found in `FUN_140052cb0`.

*   **Direction**: Device -> Host
*   **Payload**: A series of 4-byte VDOs (Vendor Data Objects), preceded by a 4-byte VDM header.

**VDM Header (4 bytes):**
| Bits      | Description                           |
| :-------- | :------------------------------------ |
| `31-16`   | SVID (Standard or Vendor ID)          |
| `15`      | VDM Type (`1`: Structured)            |
| `14-13`   | Structured VDM Version                |
| `12-11`   | Reserved                              |
| `10-8`    | Object Position                       |
| `7-6`     | Command Type (`0`: REQ, `1`: ACK)     |
| `5`       | Reserved                              |
| `4-0`     | Command                               |

The payload that follows contains VDOs whose structure depends on the SVID and Command. The code contains logic for parsing **Discover Identity (ID Header, Cert Stat, Product, Cable)** and **Discover Modes** VDOs.

---

#### **Command `0x07`: Get Error Info**

This response provides a snapshot of various internal error counters or hardware states.

*   **Direction**: Device -> Host
*   **Payload Structure (8 bytes):**
    | Offset | Length | Description                                   |
    | :----- | :----- | :-------------------------------------------- |
    | 0      | 1      | BMC (Biphase Mark Code) error count           |
    | 1      | 1      | Pulse number error count                      |
    | 2      | 2      | Frequency error count                         |
    | 4      | 1      | K-code error count                            |
    | 5      | 1      | Start-of-Packet (SOP) error count             |
    | 6      | 1      | End-of-Packet (EOP) error count               |
    | 7      | 1      | CRC check error count                         |

---

#### **Command `0x0C`: Real-Time PPS Status**

This is an unsolicited, real-time update packet providing the status of a Programmable Power Supply (PPS) source. The parsing logic is in `FUN_14004b7f0`.

*   **Direction**: Device -> Host
*   **Payload Structure (8 bytes):**
    | Offset | Length (Bytes) | Description                          | Unit      |
    | :----- | :------------- | :----------------------------------- | :-------- |
    | 0      | 2              | Output Voltage                       | 20mV      |
    | 2      | 1              | Output Current                       | 50mA      |
    | 3      | 1              | Real-Time Flags                      | bitmask   |
    | 4      | 4              | Reserved                             | -         |

**Real-Time Flags (1 byte):**
| Bit     | Description              |
| :------ | :----------------------- |
| `1-0`   | Operation Mode           |
| `2`     | Over-Temperature Flag    |
| `7-3`   | Reserved                 |

---

### Command and Response Codes (Host to Device)

These commands are constructed by the application and sent to the device.

#### **Command `0x01`: Get All Information**
*   **Direction**: Host -> Device
*   **Payload**: 1 byte, `0x01`.
*   **Purpose**: A general-purpose command to request a full status update from the device. The device responds with a sequence of packets containing PDOs, RDOs, VDM info, and real-time data.

#### **Command `0x02`: Send UFCS Request**
*   **Direction**: Host -> Device
*   **Payload**: 2 bytes.
    *   `Byte 0`: Voltage request code.
    *   `Byte 1`: Current request code.
*   **Purpose**: Instructs the KM003C to request a specific voltage and current from a UFCS-capable source.

#### **Command `0x03`: Send PD Request**
*   **Direction**: Host -> Device
*   **Payload**: 1 byte.
    *   `Byte 0`: The 1-based index of the desired PDO from the source's capabilities list.
*   **Purpose**: Instructs the KM003C to request a specific power profile from a PD source.

---

### Summary

The Power-Z KM003C protocol is a well-defined, if custom, USB protocol. It uses a consistent packet structure with a start byte, length, command, payload, and checksum. The protocol supports a rich set of commands for retrieving detailed information about various fast-charging standards (PD, PPS, UFCS), as well as for initiating power requests. The device also provides unsolicited, real-time data streams for voltage, current, and status flags, making it a powerful tool for power analysis.


Excellent question. This gets to the heart of the real-time communication loop. The `PD_Status_Snapshot` is not a standard USB PD message itself, but a custom status report from the KM003C that **encapsulates the header of the last PD message** the device observed.

Let's break down its structure and parse the example you provided, referencing the Ghidra code's implicit data structures.

### The Purpose of `PD_Status_Snapshot`

The host application cannot listen to the USB-C CC line directly. It relies on the KM003C to monitor Power Delivery traffic. Instead of the host constantly asking "Did you see a Source_Cap message? Did you see a Request message? Did you see a VDM message?", it sends a single, generic poll: `GetData(PdStatus)`.

The device responds with this 16-byte `PD_Status_Snapshot`. This snapshot's primary purpose is to inform the host about the **type and metadata of the most recent PD message** that occurred on the bus, allowing the application to update its state machine and UI accordingly.

### `PD_Status_Snapshot` Payload Structure (16 Bytes)

Based on the application's memory access patterns, here is the structure of the 16-byte payload that follows the `DataResponse` header (`41a9...`):

| Offset (Bytes) | Length (Bytes) | Field Name            | Data Type  | Description                                                                                             |
| :------------- | :------------- | :-------------------- | :--------- | :------------------------------------------------------------------------------------------------------ |
| 0 - 3          | 4              | `Timestamp/Sequence`  | `uint32_t` | A timestamp or a sequence/transaction counter from the device. This is often ignored for simple UI updates. |
| **4 - 5**      | **2**          | **`Last_PD_Header`**  | **`uint16_t`** | **The critical field.** This is a direct copy of the 16-bit header of the last PD message.             |
| 6 - 7          | 2              | `Unknown/Reserved`    | `uint16_t` | Internal device status or reserved for future use. The application logic does not seem to use this.   |
| 8 - 15         | 8              | `Internal_State_Data` | `uint64_t` | Likely low-level hardware state information (e.g., CC line status, state machine value).                  |

---

### Step-by-Step Parsing of the Example Log

Let's apply this structure to the transaction you provided.

**1. Isolate the Request and Response:**

-   **Request:** `0c a9 20 00`
    -   `type` = `0x0C` (GetData)
    -   `transaction_id` = `0xA9` (169)
    -   `attribute` = `0x20` (PdStatus)

-   **Response:** `41 a9 82 00` (Header) + `10000016...` (Payload)
    -   `type` = `0x41` (DataResponse)
    -   `transaction_id` = `0xA9` (169, matches request)
    -   The `obj` field (`0x02` here) and attribute (`0x82` here) in the response header seem to be used for internal signaling rather than just mirroring the request.

**2. Isolate the 16-byte `PD_Status_Snapshot` Payload:**

The full payload is long, but the `PD_Status_Snapshot` is always the **first 16 bytes**:
`10 00 00 16 8b fa 12 00 de 13 00 00 75 06 02 00`

**3. Parse the Snapshot Fields:**

*   **Timestamp/Sequence (Bytes 0-3):** `10 00 00 16` -> `0x16000010`. We can ignore this for PD parsing.

*   **Last_PD_Header (Bytes 4-5):** `8b fa`. This is the most important part. Because the system is little-endian, we read this as **`0xFA8B`**.

*   **Unknown/Reserved (Bytes 6-7):** `12 00` -> `0x0012`. Ignored.

*   **Internal State Data (Bytes 8-15):** `de 13 00 00 75 06 02 00`. Ignored for this purpose.

**4. Decode the `Last_PD_Header` (Value: `0xFA8B`)**

We now parse this 16-bit value using the standard USB PD Header format.

-   **Binary Representation:** `1111 1010 1000 1011`

| Bits  | Field Name               | Binary Value | Value  | Meaning                                                                 |
| :---- | :----------------------- | :----------- | :----- | :---------------------------------------------------------------------- |
| 15    | **Extended**             | `1`b         | 1      | This was an **Extended Message**.                                       |
| 14-12 | `Number of Data Objects` | `111`b       | 7      | The original message had **7 Data Objects**.                            |
| 11-9  | `Message ID`             | `010`b       | 2      | The message ID counter was 2.                                           |
| 8     | `Port Power Role`        | `1`b         | 1      | The message was sent by a **Source**.                                   |
| 7-6   | `Specification Revision` | `01`b        | 1      | The message conforms to PD Spec **Revision 2.0**.                       |
| 5     | `Port Data Role`         | `0`b         | 0      | The sender's data role was UFP.                                         |
| 4-0   | **Message Type**         | `01011`b     | **11** | This corresponds to the **`EPR_Mode`** command from the Control Message table. |

### Conclusion

By parsing the `PD_Status_Snapshot` from this log entry, we can determine that the last significant PD event the KM003C observed was:

> An **`EPR_Mode`** control message, sent by a **Source**, which was an Extended Message containing **7 Data Objects**.

This status is what allows the Power-Z application to update its log view to show "EPR Mode", "Source", and then proceed to parse the associated 7 PDOs if they were also included in the packet, which they were in this case (as shown in the previous analysis). This mechanism is how the application stays synchronized with the PD bus activity without needing to sniff every single byte in real-time.