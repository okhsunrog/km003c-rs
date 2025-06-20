## How to capture packets from USB?

```
tshark -i usbmon3 -w test5_1_pd_mode_switch.pcapng
tshark -r test5_1_pd_mode_switch.pcapng -Y "usb.bus_id == 3 && usb.device_address == 28 && usb.transfer_type == 0x03" -T fields -e frame.number -e frame.time_relative -e usb.endpoint_address.direction -e usb.capdata > test5_1_pd_mode_switch.txt
```

*Check the device bus and address with `lsusb` or `cyme`*

## Todo

- Turn into workspace, create `km003c-lib`, `km003c-cli`, `km003-egui`, `km003c-tauri` crates.
- Verify and fix auto-finding serial port by vid and pid.
- Add crate for parsing usbpd messages.


tshark -r <your_capture_file.pcapng> -T json -Y "usb.transfer_type == 0x03" > output.json
tshark -r <your_capture_file.pcapng> -V -Y "usb.transfer_type == 0x03" > output.txt
tshark -r <your_capture_file.pcapng> -T fields -E separator=, -E quote=d \
  -f "usb.transfer_type == 0x03" \
  -e frame.number -e usb.endpoint_address.direction -e usb.capdata \
  > output.csv

  tshark -r wireshark/orig_open_close.13.pcapng \
  -Y "usb.device_address == 13 && usb.capdata" \
  -T fields \
  -E separator=" | " -E header=y \
  -e frame.number \
  -e frame.time_relative \
  -e usb.endpoint_address.direction \
  -e usb.capdata


in wireshard use this display filter: usb.src contains "3.28" || usb.dst contains "3.28"

❯ sqlite3  "SELECT * FROM pd_table_key;"                 

❯ sqlite3 wireshark/orig_with_pd.sqlite ".tables"
pd_chart      pd_table      pd_table_key

❯ sqlite3 wireshark/orig_with_pd.sqlite ".schema pd_table_key"
CREATE TABLE pd_table_key(key integer);

❯ sqlite3 wireshark/orig_with_pd.sqlite ".schema pd_table"    
CREATE TABLE pd_table(Time real, Vbus real, Ibus real, Raw Blob);

❯ sqlite3 wireshark/orig_with_pd.sqlite ".schema pd_chart"
CREATE TABLE pd_chart(Time real, VBUS real, IBUS real, CC1 real, CC2 real);

❯ sqlite3 -header wireshark/orig_with_pd.sqlite "SELECT * FROM pd_table_key;"

❯ sqlite3 -header wireshark/orig_with_pd.sqlite "SELECT * FROM pd_chart;"    
Time|VBUS|IBUS|CC1|CC2
0.203|0.003|0.0|3.237|0.125
0.246|0.003|0.0|3.237|0.124
0.283|0.003|0.0|3.237|0.124
0.323|0.003|0.0|3.237|0.122
0.363|0.003|0.0|3.237|0.123
0.402|0.005|0.0|3.24|0.121
0.432|0.004|0.0|3.24|0.123
0.473|0.002|0.0|3.237|0.122


❯ sqlite3 -header wireshark/orig_with_pd.sqlite "SELECT Time, Vbus, Ibus, hex(Raw) AS RawHex FROM pd_table;"
Time|Vbus|Ibus|RawHex
4.553|0.0|0.0|45C911000011
4.831|5.088|0.069|9FDF12000000A1612C9101082CD102002CC103002CB10400454106003C21DCC0
4.833|5.088|0.069|9FE112000000A1612C9101082CD102002CC103002CB10400454106003C21DCC0
4.835|5.086|0.069|9FE312000000A1612C9101082CD102002CC103002CB10400454106003C21DCC0
4.981|5.086|0.0|9F7513000000A1632C9101082CD102002CC103002CB10400454106003C21DCC0
4.982|5.086|0.0|8776130000004102
4.986|5.086|0.0|8B7A130000008210DC700323
4.987|5.086|0.0|877B130000002101
4.991|5.086|0.0|877F13000000A305
4.991|5.086|0.0|877F130000004104
5.123|9.091|0.022|870314000000A607
5.124|9.091|0.022|8704140000004106
9.921|5.105|0.0|45C126000012


❯ sqlite3 -header wireshark/orig_with_pd.sqlite "SELECT Time, Vbus, Ibus, hex(Raw) AS RawHex FROM pd_table;"
Time|Vbus|Ibus|RawHex
4.553|0.0|0.0|45C911000011
4.831|5.088|0.069|9FDF12000000A1612C9101082CD102002CC103002CB10400454106003C21DCC0
4.833|5.088|0.069|9FE112000000A1612C9101082CD102002CC103002CB10400454106003C21DCC0
4.835|5.086|0.069|9FE312000000A1612C9101082CD102002CC103002CB10400454106003C21DCC0
4.981|5.086|0.0|9F7513000000A1632C9101082CD102002CC103002CB10400454106003C21DCC0