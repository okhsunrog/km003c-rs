# KM003C Protocol Analysis 2025-07-28

Using the `process_pcapng` example we parsed `pd_capture_new.9.pcapng` with tshark running under the `nobody` user. This produced 3462 USB captures stored in `/tmp/capture.parquet`.

The parquet data was inspected with helper examples to list packet types and check extended headers.

## Observed packet types

| Packet Type | Attribute | Count | Notes |
|-------------|----------|-------|------|
| 0x05 (Accept) | 0x0000 | 2 | response to unknown commands |
| 0x0C (GetData) | 0x0001 (Adc) | 1401 | request ADC data |
| 0x0C (GetData) | 0x0010 (PdPacket) | 310 | request PD data |
| 0x0C (GetData) | 0x0011 (unknown) | 18 | unknown request |
| **0x10 (unknown)** | 0x0001 | 1 | host command followed by Accept |
| **0x11 (unknown)** | 0x0000 | 1 | host command followed by Accept |
| 0x41 (PutData) | 0x0001 (Adc) | 1419 | ADC data responses |
| 0x41 (PutData) | 0x0010 (PdPacket) | 310 | PD event stream |

Unrecognized packet types `0x10` and `0x11` have no payload and are acknowledged with `Accept`. Attribute `0x0011` was observed with `GetData` and is currently undocumented.

## Extended header usage

All observed `PutData` packets contained the 4-byte `ExtendedHeader`. Fields matched the payload length and direction:

- ADC responses (`attribute=0x0001`) use `size=44`, sometimes with `next=true` for the first packet in a burst.
- PD event packets (`attribute=0x0010`) use varying `size` (commonly 12, occasionally 88) and always `next=false`.
- No control packets used `ExtendedHeader`.

### Forced decoding on other packet types

To verify that the extended header is exclusive to `PutData`, the first four bytes of other packet payloads were interpreted as an `ExtendedHeader`:

- `GetData` requests contain only two payload bytes, so decoding an extended header is impossible.
- `Accept` and other control packets have zero payload, giving no header candidate.
- For the few unknown control packets with four or more bytes, the decoded `size` field did not match the remaining payload length.

These tests show that only `PutData` packets carry a meaningful `ExtendedHeader`.

These observations confirm that `ExtendedHeader` is only present for `PutData` packets and its fields accurately describe the payload.

