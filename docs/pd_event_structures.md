# PD Event Structures and Packet Combinations

This document summarises the PD event packets found in the capture `matching_record/wireshark_0.7.pcapng`.

## Event Packet Layouts

### Connection Event (6 bytes)
```
+--------+-----------------+-----------+------------+
| 0x45   | Timestamp[3B]   | Reserved  | EventData |
+--------+-----------------+-----------+------------+
 byte0     bytes1..3        byte4        byte5
```
- **EventData**: upper nibble = CC pin, lower nibble = action (1=Attach, 2=Detach).

### Status Packet (12 bytes)
```
+------+-----------------+---------+---------+---------+---------+
| Type | Timestamp[3B]   | VBUS    | IBUS    | CC1     | CC2     |
+------+-----------------+---------+---------+---------+---------+
 byte0   bytes1..3         u16       u16       u16       u16
```
- **Type**: usually 0x80-0x9F when disambiguating from PD messages.
- Voltage/current fields are raw ADC readings.

### Wrapped PD Message
```
+------+-----------------+-----------+-----------+-----------------+
|Flag  | Timestamp[3B]   | Reserved  | MsgLen?   | PD Message ...  |
+------+-----------------+-----------+-----------+-----------------+
 byte0   bytes1..3         byte4-5     n/a         variable (2..32B)
```
- **Flag**: bit2 indicates direction (1=SRC→SNK).
- The PD message field contains a standard USB PD header and data objects.

## Observed Packet Combinations

Using the `pd_event_sequences` example, the capture contained the following `PutData` packet patterns:

| Packet Type | Sequence of events | Count |
|-------------|-------------------|------:|
| PdRawData   | `S`               | 347   |
| PdRawData   | `P`               | 26    |
| PdRawData   | `C`               | 2     |
| PdRawData   | *(empty payload)* | 23    |
| PdStatusData| *(none observed)* | 0     |

No combined sequences (e.g. multiple events per packet) were present.
