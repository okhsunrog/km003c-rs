# KM003C Protocol Reverse Engineering TODO List

This document tracks the tasks for reverse engineering the ChargerLAB POWER-Z KM003C protocol.

## Phase 1: Integrate New Knowledge & Refine Current Understanding

1.  **Update `src/protocol.rs` Based on `docs/protocol_reversed.md` and `Km002c接口说明`:**
    *   [ ] **CommandType Enum:**
        *   [ ] Add `CMD_DISCONNECT (0x03)`
        *   [ ] Add `CMD_JUMP_APROM (0x08)`
        *   [ ] Add `CMD_JUMP_DFU (0x09)`
        *   [ ] Add `CMD_GET_FILE (0x0E)` (Note: repurposed for streaming)
        *   [ ] Add `CMD_STOP_STREAM (0x0F)`
        *   [ ] Add `CMD_SET_CONFIG (0x10)`
        *   [ ] Add `CMD_RESET_CONFIG (0x11)`
        *   [ ] Add `CMD_GET_DEVICE_INFO (0x40)`
        *   [ ] Add `CMD_SERIAL (0x43)`
        *   [ ] Add `CMD_DATA_WITH_PAYLOAD (0x48)`
        *   [ ] Add `CMD_AUTHENTICATE_WITH_PAYLOAD (0x4C)`
        *   [ ] Resolve `0x4C`: Change `SetRecorderMode` to `CmdAuthenticateWithPayload`.
    *   [ ] **Attribute Enum:**
        *   [ ] Add `ATT_QC_PACKET (0x0040)`
        *   [ ] Add `ATT_TIMESTAMP (0x0080)`
        *   [ ] Add `ATT_SERIAL (0x0180)`
        *   [ ] Add `ATT_AUTH (0x0200)`
        *   [ ] Add `ATT_DEVICE_INFO (0x1000)`
        *   [ ] Resolve `0x0200`: Change `SwitchToPdAnalyzer` to `AttAuth`.
    *   [ ] **Command Header Structure:**
        *   [ ] Align Rust command building/parsing with `MsgHeader_TypeDef` (7 bits type, 1 bit extend, 8 bits id, 1 bit encrypted_flag, 15 bits attribute).
        *   [ ] Create Rust struct(s) for `MsgHeader_TypeDef` (ctrl, data, header variants).
        *   [ ] Clarify Host-to-Device (H->D) simple byte order header vs. Device-to-Host (D->H) bitfield structure in `src/protocol.rs` and `docs/protocol_reversed.md`.

2.  **Re-analyze `logs/orig_app_cap0.txt`:**
    *   [ ] With updated command/attribute definitions, manually re-interpret the log.
    *   [ ] Document findings and any remaining ambiguities (e.g., attribute `0x0400`, `0x0101`).
    *   [ ] Cross-reference with `wireshark/test1_1_app_open_close.txt` findings.

3.  **Review and Update `docs/protocol_reversed.md`**:
    *   [ ] Incorporate insights from `Km002c接口说明` regarding `MsgHeader_TypeDef`.
    *   [ ] Clarify bit packing for the command header, detailing the two observed types (H->D simple vs. D->H bitfield).
    *   [ ] Add any new findings from re-analyzing `orig_app_cap0.txt` and `test1_1_app_open_close.txt`.
    *   [ ] Correct Device Info retrieval: `CMD_GET_DATA (0x0C)` with `ATT_PD_PACKET (0x0010)`.
    *   [ ] Document the observed multi-step authentication flow from `test1_1_app_open_close.txt`.
    *   [ ] Add new/unclear attributes from `test1_1_app_open_close.txt` (`0x0101`, `0x0081`, `0x0581`, `0x0400`, `0x7FE1`, `0x0141`) to a list for investigation.

4.  **Evaluate `docs/protocol_guessing_old.md`**:
    *   [ ] Determine if it contains any unique information not covered by `docs/protocol_reversed.md`.
    *   [ ] If not, mark for deletion or archive.

## Phase 2: Targeted Ghidra Investigation (using MCP)

*Goal: Understand logic, request/response flow, and command sequences.*

1.  **Unknown Attributes (from captures & Ghidra):**
    *   [ ] `0x0101` (H->D `CMD_AUTHENTICATE`; D->H `CMD_AUTHENTICATE_WITH_PAYLOAD` response attribute)
    *   [ ] `0x0400` (H->D `CMD_GET_DATA` post-auth attribute)
    *   [ ] `0x0081` (D->H `CMD_AUTHENTICATE` response attribute)
    *   [ ] `0x0581` (D->H `StatusA` for device info response attribute)
    *   [ ] `0x7FE1` (D->H `StatusA` for `CMD_GET_DATA` with `attr=0x0400` response attribute)
    *   [ ] `0x0141` (D->H `StatusA` for ADC data response attribute)
    *   For each:
        *   [ ] Find Ghidra function constructing the command (if H->D) or handling the response.
        *   [ ] Determine its purpose and document in `docs/protocol_reversed.md`.
        *   [ ] Add to `Attribute` enum in `src/protocol.rs` (possibly with temporary/descriptive names).

2.  **Sample Rate Configuration (`CMD_SET_CONFIG (0x10)`, `ATT_SETTINGS (0x0008)`)**:
    *   [ ] **Goal:** Find UI event handlers for sample rate changes.
    *   [ ] **Goal:** Trace to `CMD_SET_CONFIG (0x10)` + `ATT_SETTINGS (0x0008)` construction.
    *   [ ] **Goal:** Reverse engineer the payload structure, identifying byte(s) for sample rate index.
    *   [x] Decompile `set_pd_sniffer_mode @ 14006ee32` (known to use `CMD_SET_CONFIG`).
        *   Function seems specific to mode switching (e.g., PD sniffer on/off using an attribute like 0x0200 for CMD_SET_CONFIG, or CMD_RESET_CONFIG if mode is 0).
        *   Does not appear to handle ATT_SETTINGS (0x0008) or sample rate payloads directly.
    *   [x] Search Ghidra for function names related to settings/rate (e.g., "Setting", "Config", "Rate", "Sample", "SPS"). (Yielded no direct app-specific functions)
    *   [x] Search Ghidra for strings like "SPS", "kSPS", "Sample Rate" and check their Xrefs.
        *   Found "spsGroupBox", "10SPS", "50SPS", "1KSPS", "10KSPS".
        *   Found "1onSPSChanged(int,bool)" (slot signature at `14017aa38`) and "onSPSChanged".
        *   Xrefs to "spsGroupBox" led to `FUN_14001df90` (UI setup, timed out decompiling).
        *   Xrefs to "1onSPSChanged(int,bool)" led to `FUN_140016940`.
    *   [x] Decompile `FUN_140016940` (references "1onSPSChanged(int,bool)").
        *   This function sets up QPushButtons for sample rates (1, 10, 50, 1k, 10k SPS, with IDs 0-4) in a QButtonGroup.
        *   Connects `QButtonGroup::idToggled(int,bool)` signal to `param_1`'s slot `onSPSChanged(int,bool)` (using string `1onSPSChanged(int,bool)` at `14017aa38`).
        *   The `int` argument to the slot is the sample rate index (0-4).
    *   [ ] **Next:** Find the implementation of the `onSPSChanged(int, bool)` slot.
        *   This slot receives the sample rate index.
        *   It should then construct `CMD_SET_CONFIG (0x10)` with `ATT_SETTINGS (0x0008)` and the payload.
    *   [ ] Trace `CMD_SET_CONFIG (0x10)` with `ATT_SETTINGS (0x0008)` usage to find payload construction.
        *   [x] Identified `send_command_with_payload @ 14006ed00` as the function that sends commands with payloads.
            *   Signature: `send_command_with_payload(comm_obj, attribute_ushort, payload_qbytearray_ptr)`
            *   Xrefs to it (`14027aa78`, `140184208`) are data pointers.
            *   `140184208` is an entry in `UsbPolicyMX::vftable`, meaning `send_command_with_payload` is its 27th virtual method (index 26).
        *   [ ] **Next (On Hold):** Find calls to this virtual method of `UsbPolicyMX` where `attribute == 0x0008`. This call is expected to be in `DeviceView::onSPSChanged`.
            *   This requires more advanced Ghidra exploration (e.g., analyzing MOC-generated code like `DeviceView::qt_static_metacall` or detailed vtable call tracing).

3.  **Serial Command Encapsulation (`CMD_SERIAL (0x43)`, `ATT_SERIAL (0x0180)`)**:
    *   [x] Fully decompile `build_serial_command_packet @ 14006bd10` using Ghidra MCP. (Completed 2025-06-19)
    *   [x] Document the exact structure of the fixed 8-byte payload header. (Already well-documented in `docs/protocol.md`)
    *   [x] Document how `command_string`, `UUID`, `timestamp`, and "LYS" suffix are formatted. (Already well-documented in `docs/protocol.md`)
    *   [x] Update `docs/protocol.md` with these details. (No major updates needed to `docs/protocol.md` as existing info was sufficient; `docs/ghidra.md` updated with function entry).

4.  **Authentication Protocol (`CMD_AUTHENTICATE_WITH_PAYLOAD (0x4C)`, `ATT_AUTH (0x0200)`)**:
    *   [x] Decompile `send_auth_packet_and_verify @ 14006e9e0`. (Completed 2025-06-19)
        *   Identified challenge construction: `[timestamp (8B)] + [conditional_data (var, depends on auth step)] + [random_nonce (8B)]`.
        *   Identified call to `FUN_14006b860` for command building & payload encryption.
        *   Identified call to `get_crypto_key` and a subsequent key modification (`key_byte_1 = 'X'`) *during response decryption*.
        *   Identified response decryption and verification against original timestamp & nonce.
    *   [x] Decompile `FUN_14006b860` (builds full auth command & encrypts payload). (Completed 2025-06-19)
        *   Confirms header `0x4C` (CMD_AUTHENTICATE_WITH_PAYLOAD) with `ATT_AUTH (0x0200)`.
        *   Encrypts challenge payload using key from `get_crypto_key` (key used *without* 'X' modification here).
        *   Appends 32-byte encrypted payload to header.
    *   [x] Decompile or analyze `get_crypto_key` (to understand AES key source/derivation). (Completed 2025-06-19)
        *   Function `get_crypto_key @ 1400735e0` retrieves one of at least four 16-byte keys based on an integer index.
        *   Keys are hardcoded in the data segment (e.g., key for auth index 3 from `DAT_140184b60 + 0x16`).
    *   [x] Extract actual byte values of the hardcoded AES keys. (Completed 2025-06-19 using `xxd` on `Mtools.exe` provided by user).
        *   Key values added to `docs/ghidra.md`.
    *   [ ] Document detailed challenge, encrypted payload, and decrypted response payload structures in `docs/protocol.md`.
    *   [ ] Document the key modification detail (`*key_byte_1 = 'X'` for decryption) and hardcoded key findings in `docs/protocol.md`.
    *   [ ] Update `docs/protocol.md` section on Authentication Protocol with these findings.

5.  **Device Information Block (`CMD_GET_DEVICE_INFO (0x40)`, `ATT_DEVICE_INFO (0x1000)`)**:
    *   [ ] Decompile `get_info_block @ 14006de50` and `FUN_14006b580`.
    *   [ ] Precisely map the 200+ byte device information block structure.
    *   [ ] Create a Rust struct in `src/protocol.rs` to parse this block.
    *   [ ] Update `docs/protocol_reversed.md`.

6.  **Other Key Functions from `docs/protocol_reversed.md` "Next Analysis Targets":**
    *   [ ] `FUN_14006c9c0` - ADC data processing.
    *   [ ] `FUN_140161150` - PD packet processing.
    *   [ ] Device info parsing and field extraction logic (if not fully covered by point 4).

## Phase 3: Wireshark Capture Analysis

*Goal: Understand command flow, sequences, and real-world usage patterns.*

1.  **List and Prioritize Wireshark Captures:**
    *   [ ] `wireshark/test1_1_app_open_close.txt` (Analyzed)
    *   [ ] `wireshark/test1_2_app_disconnect.txt`
    *   [ ] `wireshark/test2_1_set_rate_10sps.txt`
    *   [ ] `wireshark/test4_1_online_chart_all.txt`
    *   [ ] `wireshark/test5_1_pd_mode_switch.txt`
    *   [ ] `wireshark/test5_2_pd_capture.txt`
    *   [ ] `wireshark/rate_cycling_test_all.txt` (if different from others)

2.  **For each capture file:**
    *   [ ] Analyze the sequence of commands (Host -> Device) and responses (Device -> Host).
    *   [ ] Correlate with known command types and attributes.
    *   [ ] Identify typical command flows for specific operations (e.g., connecting, setting rate, starting PD capture).
    *   [ ] Note any unknown commands, attributes, or data payloads.
    *   [ ] Document findings in `docs/protocol_reversed.md` under a new "Command Sequences" or "Usage Scenarios" section.
    *   [ ] Add any new ambiguities or questions to this TODO list for Ghidra investigation.

## Phase 4: Experimentation and Verification (Rust Library Implementation)

1.  **Implement Basic Commands:**
    *   [ ] `CMD_CONNECT (0x02)`
    *   [ ] `CMD_DISCONNECT (0x03)`
    *   [ ] `CMD_ACCEPT (0x05)` (Handling responses)
2.  **Implement Data Request:**
    *   [ ] `CMD_GET_DATA (0x0C)` with `ATT_ADC (0x0001)`.
3.  **Implement Stream Management:**
    *   [ ] `CMD_GET_FILE (0x0E)` (as start stream)
    *   [ ] `CMD_STOP_STREAM (0x0F)`
4.  **Implement Configuration:**
    *   [ ] `CMD_SET_CONFIG (0x10)`
    *   [ ] `CMD_RESET_CONFIG (0x11)`
5.  **Implement Device Info Retrieval:**
    *   [ ] `CMD_GET_DATA (0x0C)` with `ATT_PD_PACKET (0x0010)` (corrected command).
6.  **Implement Serial Command Sending (Advanced):**
    *   [ ] `CMD_SERIAL (0x43)` with `ATT_SERIAL (0x0180)` and correct payload structure.
7.  **Implement Authentication (Very Advanced):**
    *   [ ] `CMD_AUTHENTICATE (0x44)`
    *   [ ] `CMD_AUTHENTICATE_WITH_PAYLOAD (0x4C)` (if crypto is understood).

## Phase 5: Experimental Testing (Live Device Interaction)

*Goal: Verify understanding by interacting directly with the device.*

*   [ ] Create and run small Rust programs in `src/bin/` (e.g., modifying `simple_logger.rs` or creating new ones) to test specific commands and observe device behavior.
    *   [ ] Test `CMD_DISCONNECT (0x03)`.
    *   [ ] Test individual authentication steps if possible.
    *   [ ] Test `CMD_GET_DATA` with various known and unknown attributes.
    *   [ ] Test serial command sending once the encapsulation is clearer.
*   [ ] Note: The `simple_logger.rs` currently uses hardcoded auth payloads and a potentially incorrect `SetRecorderMode` command. This will need updating as understanding improves.
*   [ ] Consider simplifying or removing the `fmt::Display for SensorDataPacket` if it's not crucial for debugging.

## Documentation & Project Maintenance

*   [x] Restructure `docs/` directory (Completed 2025-06-19):
    *   Created `docs/protocol.md` (consolidated from `protocol_reversed.md` and `protocol_guessing_old.md`).
    *   Created `docs/ghidra.md` for Ghidra-specific notes.
    *   Created `docs/llm.md` for AI/developer context.
    *   Deleted `docs/protocol_guessing_old.md` and `docs/protocol_reversed.md`.
*   [ ] Continuously update `docs/protocol.md` with new findings.
*   [ ] Create diagrams for command flows if helpful.
*   [ ] Document the structure of all known data payloads.
