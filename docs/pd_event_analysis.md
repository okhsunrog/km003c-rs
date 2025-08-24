# KM003C PD Event/Status Reverse Engineering Log

This document tracks a fresh analysis of the PD status/event parsing used by the ChargerLAB POWER‑Z KM003C. The goal is to derive a precise specification of the "inner event stream" and reconcile it with the Rust implementation in `km003c-lib/src/pd.rs`.

## Objectives
- Identify exact inner header layout, field meanings, and byte order.
- Enumerate all event types (connection, status, PD-wrapped, others if any) and their sizes.
- Clarify ambiguous bytes/flags (direction, size, timestamp width, SOP type bits, etc.).
- Validate against the Windows app (`Mtools.exe`) and on-disk captures.
- Produce corrected Rust structs/parsing and minimal tests.

## Working Assumptions (to verify)
- Inner events are concatenated; each has a fixed 6-byte header when PD-wrapped; status may be 12 bytes.
- Connection events identified by leading byte `0x45`.
- PD messages may be prefixed with direction/flags (0x80–0x9F range seen); timestamp likely 24-bit LE.
- Attributes: `PdStatus` (0x20) and `PdPacket` (0x40) both carry the same inner stream but different semantics/frequency.

## Questions / Unknowns
- Is the first byte a type discriminator for all inner events, or only certain ones?
- Do status packets always have 12 bytes, or can they vary?
- Exact meaning of high-bit in size or type (flagging PD vs non-PD)?
- How is SOP type encoded (if present) and where?

## Method
1) Search decompiled `Mtools.exe` for attribute cases (0x20/0x40) and constants like 0x45.
2) Extract parser function(s) and reconstruct struct layouts.
3) Cross-check with captured `packet_log.csv` and existing docs.
4) Update Rust parsing and add notes/tests.

## Findings (running log)
- [ ] T0: Locate main handler switch that processes attributes 0x20/0x40/ADC.
- [ ] T1: Identify function(s) that iterate inner event stream and switch on first byte/flags.
- [ ] T2: Confirm timestamp width and endian.
- [ ] T3: Determine PD wrapper header: direction bit, SOP, and length computation.
- [ ] T4: Catalog all event type IDs and fixed sizes.
- [ ] T5: Validate against example captures.

## Next Steps
- Use MCP to search decompilation for `0x45`, `0x20`, `0x40`, and event loop patterns.
- Draft corrected struct/enum once header is confirmed.

---
(Keep appending concrete evidence snippets and offsets from Ghidra here.)


### Evidence from Mtools.exe (Ghidra)
- Outer handler `handle_response_packet` splits composite `PutData` by `attribute` and `next` flag.
  - `attribute == 0x10` and `0x40` emit a PD data signal with the full payload.
- UI/event dispatcher `FUN_14005a070` parses the PD payload:
  - First 12 bytes are ADC/status words: u16 at +4 (VBUS), s16 at +6 (IBUS), u16 at +8 (CC1), u16 at +10 (CC2).
  - Then an inner event stream from offset 0x0C.
  - Each event starts with an 8-byte header read as a u64 (`local_168`).
    - Byte 0..3: 32-bit timestamp/tick.
    - Byte 6: length of following event data; total record size = `len + 8`.
    - Byte 4/5/7: status/type/flags (used for display; `status` keyword logged when high bits at byte0 are set).
  - PD-wrapped records are identified by markers and CRC:
    - Byte 8 == 0xAA and Byte 13 == 0xAA.
    - CRC computed over bytes 9..11 matches Byte 12.
    - Additional check: `(byte10 & 0x07) == 0` (likely SOP type == SOP).
    - On success, the code:
      - Decreases header Byte6 by 5.
      - Overwrites bytes 0..6 in the slice: writes relative-time (4 bytes), zeros at [4..5], and kind 0x05 at [6].
      - Drops 0x0D bytes from the slice (removing PD wrapper prelude), then prepends the 8-byte header.
  - Display/parser `FUN_140063a50`:
    - Distinguishes PD vs non-PD by `pcVar9[8] == 0xAA` (PD) and overall length >= 12.
    - Uses bytes [9..13] to interpret PD fields and validate (`FUN_140064cc0`) vs a parsed PD header.
    - Derives role/source/cable from `(byte9 >> 5) & 3`, prints `V%1` from `(u16{byte10,byte9} >> 3) & 0x3F`.
    - Hides certain rows when `(byte10 & 7) == 0` and `byte11 == 1`.

Implication: the inner event record format is not a simple 6-byte header + payload. It is:
- 8-byte event meta header, then variable payload.
- PD messages carry an additional 0x0D-byte wrapper `AA | hdr3 | crc | AA` before the standard PD header/data.
- Non-PD status/connection events use the same 8-byte header with `len` and a smaller body.

## Inner Record Format (consolidated)
- Meta header (8 bytes):
  - [0..=3]: u32 timestamp (ticks), little-endian
  - [4]: flags/status (used by UI; DP/DM bit encoded here)
  - [5]: flags/status (unknown semantics)
  - [6]: u8 payload length (body size, not including the 8-byte header)
  - [7]: flags/status (unknown semantics)
- Body (variable `len` bytes): one of
  - Connection event: first byte `0x45`, then at least 1 byte of event data (lower 4 bits action; upper 4 bits CC pin)
  - Status update: 8 bytes as 4 x u16 LE: VBUS, IBUS (signed), CC1, CC2
  - PD-wrapped: 0x0D-byte prelude + PD header/data

### PD Prelude Wrapper
- Body layout when PD is present (indices relative to body start):
  - [0] = `0xAA`
  - [1..=3] = 3-byte header (contains direction bit at `[1] & 0x04`, SOP info at `[2] & 0x07`)
  - [4] = CRC-8 over `[1..=3]` with poly `0x29`, init `0x00`
  - [5] = `0xAA`
  - [6..=12] = auxiliary bytes (purpose unknown)
  - [13..] = standard USB-PD message (16-bit header + data objects)
- Validation checks (from binary):
  - `body[0] == 0xAA` and `body[5] == 0xAA`
  - `(body[2] & 0x07) == 0` (SOP)
  - `crc8_0x29(body[1..=3]) == body[4]`
- Normalization done by app:
  - Decrease meta header `[6]` by `5`
  - Overwrite first 7 bytes of the event slice with: `[0..=3]` relative time (ms), `[4]=0`, `[5]=0`, `[6]=0x05`
  - Drop the first `0x0D` bytes of body before storing/displaying; prepend 8-byte meta header

### Parser decisions implemented
- Parse meta header and loop records using `[6]` for body length; timestamp is `[0..=3]`.
- Detect PD via prelude markers/CRC and yield `WrappedPdMessage { is_src_to_snk: (body[1] & 0x04)!=0, pd_bytes: &[13..] }`.
- Treat `body[0]==0x45` as a connection event and decode `event_data`.
- If `body.len() >= 8` and not PD/connection, parse status as `u16x4`.
- Unknown short bodies are ignored (EOF for stream).

### TODO
- Map flag bits in meta header bytes [4], [5], [7] (DP/DM, role/source/cable).
- Confirm whether non-SOP packets appear and how SOP' is encoded.
- Reconcile UI field extraction in `format_pd_cc_row` with a documented struct.
