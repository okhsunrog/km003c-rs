# POWER-Z KM003C Rust Library & Applications

This repository contains initial attempts at reverse-engineering the **ChargerLAB POWER-Z KM003C** USB-C power analyzer protocol and creating open-source cross-platform applications for it.

## Overview

The POWER-Z KM003C is a USB-C power analyzer that can measure voltage, current, power, and capture USB Power Delivery (PD) messages. This project provides:

- **Cross-platform Rust library** for communicating with the KM003C device
- **Command-line tools** for data acquisition and monitoring
- **GUI application** with real-time plotting capabilities
- **Protocol analysis tools** for parsing captured data

## Features

### 🔌 Device Communication
- USB HID communication with KM003C device (VID: 0x5FC9, PID: 0x0063)
- Cross-platform USB access using `nusb` (no libusb dependency)
- Asynchronous communication using Tokio
- Automatic device discovery and connection management
- Error handling and retry logic

### 📊 ADC Data Acquisition
- Real-time voltage, current, and power measurements
- Support for multiple sample rates (1, 10, 50, 1000, 10000 SPS)
- Temperature monitoring
- USB data line voltage measurements (D+, D-)
- USB CC line voltage measurements (CC1, CC2)
- Internal voltage monitoring

### ⚡ USB Power Delivery (PD) Support
- Capture and parse USB PD messages
- Connection event detection (attach/detach)
- Periodic status updates
- Full PD message parsing using the `usbpd` crate
- Support for source capabilities, data objects, and control messages

### 🛠️ Applications

#### Command Line Tools
- **`adc_simple`**: Simple ADC data reading and display
- **`pd_monitor`**: Real-time PD message monitoring with various output formats

#### GUI Application
- **Real-time plotting** of voltage and current over time
- **Live status display** with connection information
- **Cross-platform** using egui framework
- **Configurable data retention** and display options

#### Analysis Tools
- **PCAP/PCAPNG processing** for offline analysis
- **SQLite parsing** for reverse-engineering PD message wrappers from proprietary app exports
- **TShark integration** for packet analysis
- **Parquet file support** for efficient data storage



## Quick Start

### Prerequisites

- Rust 1.85 or newer with Cargo
- USB access permissions (may require udev rules on Linux)
- POWER-Z KM003C device

### Installation

```bash
# Clone the repository
git clone https://github.com/okhsunrog/km003c-rs.git
cd km003c-rs

# Update Rust to the latest stable version if needed
rustup update stable

# Build all components
cargo build --release
```

### Linux USB Permissions

Create a udev rule to allow non-root access to the device:

```bash
# Copy the provided udev rule
sudo cp 99-powerz-km003c.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
sudo udevadm trigger
```

### Usage Examples

#### Simple ADC Reading
```bash
# Read current voltage, current, and power
cargo run --bin adc_simple
```

#### PD Message Monitoring
```bash
# Monitor PD messages at 1Hz
cargo run --bin pd_monitor --frequency 1.0

# Save output to file with timestamps
cargo run --bin pd_monitor --frequency 0.5 --output pd_log.txt --timestamp

# Hex-only output for script processing
cargo run --bin pd_monitor --hex-only
```

#### GUI Application
```bash
# Launch the real-time plotting application
cargo run --bin km003c-egui
```

#### SQLite Analysis
The proprietary Windows application can export PD analysis data to SQLite format. This project includes tools to parse these exports for reverse-engineering PD message wrapper formats:

```bash
# Example SQLite export structure from proprietary app:
# Tables: pd_chart, pd_table, pd_table_key
# 
# pd_chart: Time, VBUS, IBUS, CC1, CC2 (voltage/current readings)
# pd_table: Time, Vbus, Ibus, Raw (PD messages as hex blobs)
# pd_table_key: key (metadata)

# Parse and analyze exported SQLite files
cargo run --example sqlite_pd -- path/to/export.sqlite
```

## Protocol Details

This protocol was reverse-engineered using **Wireshark with usbmon** for USB traffic analysis and **Ghidra** to analyze the original proprietary Qt-based Windows application. See [Protocol Description](docs/protocol.md) for detailed technical documentation.

## Development Status

This is an **initial attempt** at reverse-engineering the KM003C protocol. The implementation includes:

✅ **Working Features:**
- Basic device communication
- ADC data acquisition
- PD message capture
- Real-time GUI plotting
- Command-line tools

🔄 **In Progress:**
- Protocol documentation
- Additional command support
- Advanced analysis features

❓ **Unknown/Unimplemented:**
- Device configuration commands
- Advanced measurement modes
- Firmware update protocol
- Some proprietary features
## TODO
- Handle tshark root warning in examples
- Investigate packet types 0x10 and 0x11


## Contributing

This is a reverse-engineering project. Contributions are welcome for:

- Protocol analysis and documentation
- Additional command implementations
- Bug fixes and improvements
- New analysis tools
- Cross-platform compatibility

## Disclaimer

This is an unofficial reverse-engineering effort. Use at your own risk. The author is not affiliated with ChargerLAB. 