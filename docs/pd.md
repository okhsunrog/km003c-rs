Excellent. Capturing all this hard-won knowledge in one place is the perfect way to pause and resume the project. Here is the comprehensive, updated cheat sheet incorporating everything we've discovered.

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

## 4. Ghidra Function Reference (The Decoder's Roadmap)

The application's logic for parsing the PD data stream is concentrated in these key functions. Replicating their logic in Rust is the path to a full implementation.

-   **`FUN_140045b20` (The Main Loop):**
    -   **Role:** The Qt slot connected to the polling timer. This is the entry point for processing incoming data.
    -   **Action:** It dequeues a raw USB payload, parses the 12-byte `PdWrapperPacket` header for live values, then iterates through the remaining bytes, processing each `PdMessage` block it finds.

-   **`FUN_14004cbc0` (The Header Parser):**
    -   **Role:** Decodes the 16-bit raw PD message header.
    -   **Action:** Takes the `u16` from `PdMessage[1-2]` and extracts fields like `MessageType`, `NumberOfDataObjects`, `SpecificationRevision`, `PortDataRole`, etc., via bit-masking and shifting.

-   **`FUN_14004d170` (The Message Dispatcher):**
    -   **Role:** A large `switch` statement that acts as a central router.
    -   **Action:** It inspects the `MessageType` (the lower 5 bits of the header) and calls the appropriate specialized parsing function for that message.

### 4.1. Message-Specific Parsers

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