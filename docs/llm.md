# LLM Context & Learnings for KM003C Project

This document captures key insights, "gotchas," "aha-moments," and important context to help future AI assistants (or human developers) get up to speed quickly on this project.

## Project Goal

Reverse engineer the USB protocol for the ChargerLAB POWER-Z KM003C device to create an open-source library.

## Key Discoveries & Aha-Moments

*   **Virtual Method Calls:** Identifying `send_command_with_payload` as a virtual method of `UsbPolicyMX` was a key step. Direct xrefs were misleading; vtable analysis was required.
*   **Qt Signal/Slot Mechanism:** Understanding how Qt connects signals to slots using string signatures (e.g., `"1onSPSChanged(int,bool)"`) was crucial for tracing UI events to handler code. Functions like `FUN_140016940` (UI setup) and `FUN_140014860` (class constructor/init) were key to finding these connections.
*   **Sample Rate UI:** The sample rate is selected via a `QButtonGroup` of `QPushButtons`, providing an index (0-4) to the `onSPSChanged(int,bool)` slot in the `DeviceView` class.

## Gotchas & Common Pitfalls

*   **Ghidra MCP Tool Timeouts:** Some larger functions may time out during decompilation via MCP. Retries or alternative analysis methods (like examining callers/callees or related string/data xrefs) may be needed.
*   **Indirect Xrefs:** Be aware that cross-references (Xrefs) to functions might be indirect (e.g., through vtables or function pointers stored in data). `[DATA]` xrefs require further investigation to find the actual call sites.
*   **Function Naming:** Ghidra's default `FUN_` names require careful reverse engineering to assign meaningful names. Renaming functions in Ghidra as they are understood is highly beneficial.

## Current State of Investigation (as of [Current Date/Time])

*   (Summary of what's currently being worked on or major unresolved questions)
*   Currently focusing on understanding the payload for `CMD_SET_CONFIG` with `ATT_SETTINGS` for sample rate changes. The UI to handler path is mostly understood up to the point of calling `DeviceView::onSPSChanged`. The next step is finding the implementation of this slot and how it calls `UsbPolicyMX::send_command_with_payload`. This is currently on hold pending more advanced Ghidra exploration.
*   Documentation rework is in progress.

## Important Files for Context

*   `docs/protocol.md`: Main protocol documentation (to be created).
*   `docs/ghidra.md`: Specific Ghidra RE notes.
*   `docs/todo.md`: Current task list.
*   `src/protocol.rs`: Rust implementation of protocol constants.
