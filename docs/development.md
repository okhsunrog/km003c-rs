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