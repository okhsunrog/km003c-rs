# PD Connection Events and Message Flow

This document cross-references the `matching_record/export.sqlite` database with the `wireshark_0.7.pcapng` capture to locate connection events and decode the USB Power Delivery message exchange.

## Connection Events

The SQLite `pd_table` contains two `ConnectionEvent` entries. The payload format is `45 <timestamp:3B> 00 <event>` where the event byte encodes the CC pin (upper nibble) and action (lower nibble).

| Time (s) | Event |
|---------:|-------|
| 5.834 | Attach on CC2 |
| 15.290 | Detach on CC2 |

A binary scan of the pcap confirmed both patterns:

| Event Hex | Offset in pcap |
|-----------|---------------|
| `45CA16000021` | 91152 |
| `45BA3B000022` | 203592 |

## PD Message Sequence

Parsing the remaining PD packets (wrapper byte `0x8?`) reveals the following ordered exchange:

1. SNK→SRC `VendorDefined`
2. SRC→SNK `GoodCRC`
3. SNK→SRC `VendorDefined`
4. SRC→SNK `GoodCRC`
5. SRC→SNK `SourceCapabilities`
6. SRC→SNK `GoodCRC`
7. SNK→SRC `Request`
8. SRC→SNK `GoodCRC`
9. SRC→SNK `Accept`
10. SRC→SNK `GoodCRC`
11. SRC→SNK `PsRdy`
12. SRC→SNK `GoodCRC`
13. SNK→SRC `VendorDefined`
14. SRC→SNK `GoodCRC`
15. SRC→SNK `NotSupported`
16. SRC→SNK `GoodCRC`
17. SRC→SNK `GetSinkCap`
18. SRC→SNK `GoodCRC`
19. SRC→SNK `NotSupported`
20. SRC→SNK `GoodCRC`

### Message Type Counts

| Message Type      | Count |
|------------------|------:|
| VendorDefined     | 3 |
| SourceCapabilities| 1 |
| Request           | 1 |
| Accept            | 1 |
| PsRdy             | 1 |
| GetSinkCap        | 1 |
| NotSupported      | 2 |
| GoodCRC           | 10 |

No `PdStatusData` packets were observed; all events came through `PdRawData`.
