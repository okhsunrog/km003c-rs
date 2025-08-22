# PD Parsing Notes

## Matching SQLite and Wireshark Data
- SQLite `pd_table` rows contain an inner event stream used in USB `PutData` packets. Example row:
  - `9F9B1C000000A1612C9101082CD102002CC103002CB10400454106006421DCC0`
- Wireshark capture shows `PutData` packets where, after an 8-byte header, the same event bytes appear. This confirms the mapping between database and USB traffic.
- Timestamps differ between sources but event ordering is consistent.

## Parser Observations
- Inner stream contains three record types:
  1. `0x45` connection events (6 bytes)
  2. Status updates (12 bytes) with voltage/current readings
  3. `0x80–0x9F` PD message wrappers followed by a standard USB PD message
- Some `PutData` packets in the capture use attribute `PdStatus (0x20)` to carry only periodic status records.
- The library previously ignored `PdStatus` packets; only `PdPacket` was exposed.

## Implemented Changes
- Added `PdStatusData` and `CmdGetPdStatus` variants to `Packet` so callers can request and receive the status stream.
- Refactored `to_raw_packet` to share header-building logic for PD packet and status responses.
- Parsed `ExtendedHeader` once during `RawPacket` construction and stored it in the `Data` variant to avoid redundant slicing when accessing attributes or payload.

## Ideas and Next Steps
- Use `parse_event_stream` on `PdStatusData` to feed real-time voltage/current into analysis tools.
- Explore remaining unknown packet type `0x44` seen in capture.
- Investigate timestamp origin to align pcap and SQLite traces precisely.
