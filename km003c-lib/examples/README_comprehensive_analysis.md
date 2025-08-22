# Comprehensive KM003C Protocol Analysis Tool

This tool provides **complete analysis** of KM003C USB traffic by capturing **ALL USB transfers** (control, data, interrupt, bulk) and providing detailed analysis of each packet.

## What It Does

Unlike the basic `pcap_to_csv.rs` which only captures data transfers, this tool:

1. **Captures ALL USB traffic** - Control transfers, data transfers, interrupt transfers, bulk transfers
2. **Analyzes each packet** - Shows where data comes from and what it means
3. **Provides detailed breakdown** - USB setup data, endpoint information, transfer types
4. **Generates comprehensive reports** - CSV, Markdown, and detailed analysis files

## Why This Matters

The basic tool missed **connection events** because they come through **USB control transfers** (type 0x02), not data transfers (type 0x03). This comprehensive tool will show you:

- **CC attach/detach events** (control transfers)
- **Command packets** (control transfers) 
- **ADC data** (interrupt transfers)
- **PD data** (interrupt transfers)
- **All USB setup data** and protocol details

## Usage

```bash
cargo run --example comprehensive_pcap_analysis -- -f your_capture.pcapng
```

### Options

- `-f, --file`: Input pcapng file (required)
- `--csv`: Output CSV file (default: `comprehensive_analysis.csv`)
- `--md`: Output Markdown file (default: `comprehensive_analysis.md`)
- `--analysis`: Output detailed analysis file (default: `detailed_analysis.txt`)

## Output Files

### 1. CSV File (`comprehensive_analysis.csv`)
Contains all packets with columns:
- `frame`: Frame number
- `time`: Timestamp
- `usb_transfer_type`: USB transfer type (0x00=Control, 0x01=Isochronous, 0x02=Control, 0x03=Interrupt, 0x04=Bulk)
- `usb_endpoint`: USB endpoint address
- `direction`: H->D (Host to Device) or D->H (Device to Host)
- `usb_setup_data`: USB setup data (for control transfers)
- `usb_capdata`: USB payload data
- `hex_data`: Hex representation of data
- `raw_packet`: Raw KM003C packet parsing result
- `packet`: High-level KM003C packet parsing result
- `event_detail`: Detailed event information
- `analysis_notes`: Analysis of what the packet contains
- `data_source`: Where the data comes from
- `protocol_layer`: Protocol layer information

### 2. Markdown File (`comprehensive_analysis.md`)
Formatted table view of all the CSV data for easy reading.

### 3. Detailed Analysis File (`detailed_analysis.txt`)
Detailed breakdown of each packet with:
- USB transfer type and description
- Endpoint information
- Direction and meaning
- Setup data analysis (for control transfers)
- Data payload analysis
- KM003C protocol analysis
- Summary statistics

## What You'll See Now

With this tool, you should now see:

### Control Transfers (Connection Events)
```
Frame 123 - 1.234567s
USB Transfer Type: 0x02 (Control)
Endpoint: 0x00 (EP0)
Direction: H->D (Host to Device)
Setup Data: 80:06:00:01:00:00:40:00
Analysis: Setup: Type=0x80, Req=0x06, Val=0x0001, Idx=0x0000, Len=64
Data Source: USB Setup Stage
Protocol Layer: USB Control Transfer
```

### Data Transfers (ADC/PD)
```
Frame 124 - 1.234789s
USB Transfer Type: 0x03 (Interrupt)
Endpoint: 0x81 (EP1 IN)
Direction: D->H (Device to Host)
Data: 48:01:00:00:10:00:00:00:2C:00:00:00...
Analysis: Data: Type=0x48, Flag=true, ID=1, Attr=16, Size=44
Data Source: Device Interrupt Endpoint | KM003C Control Packet
Protocol Layer: USB Interrupt Transfer | KM003C Protocol
```

## Key Insights

1. **Connection events are control transfers** - Look for transfer type 0x02
2. **ADC/PD data are interrupt transfers** - Look for transfer type 0x03  
3. **USB setup data reveals commands** - Parse the 8-byte setup packets
4. **Endpoint addresses show data flow** - 0x00=control, 0x81=EP1 IN, 0x01=EP1 OUT

## Example Analysis

When you see a packet like:
```
usb_transfer_type: 0x02
usb_setup_data: 80:06:00:01:00:00:40:00
```

This means:
- **Control transfer** (0x02)
- **Device descriptor request** (0x06)
- **Standard request** (0x80)
- **Get descriptor** for device (0x01)

## Troubleshooting

If you still don't see connection events:
1. **Check USB capture settings** - Make sure you're capturing ALL USB traffic
2. **Verify device enumeration** - Connection events happen during USB enumeration
3. **Look for control transfers** - Connection events are control transfers, not data transfers

This tool should reveal the complete KM003C protocol picture that was hidden before!
