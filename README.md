# km003c-rs

Rust library and applications for the **ChargerLAB POWER-Z KM003C** USB-C power analyzer.

## Overview

`km003c-rs` provides a cross-platform Rust implementation for communicating with the KM003C device, enabling real-time USB-C power analysis and USB Power Delivery message capture.

## Features

### Device Communication
- Dual interface support: Vendor (bulk, ~0.6ms latency) or HID (interrupt)
- Cross-platform support using `nusb`
- Asynchronous communication with Tokio
- Automatic device discovery, initialization, and authentication

### ADC Data Acquisition
- Real-time voltage, current, and power measurements
- Two modes:
  - **Simple ADC**: Single-shot readings with temperature and statistics
  - **AdcQueue streaming**: High-speed continuous streaming (2, 10, 50, 1000 SPS)
- USB data line voltage measurements (D+, D-)
- USB-C CC line voltage measurements (CC1, CC2)

### USB Power Delivery Support
- Capture and parse USB PD messages
- Connection/disconnection event detection
- Full PD message parsing using the `usbpd` crate
- Support for SPR and EPR source capabilities
- Chunked message reassembly for EPR

### Device Information
- Model, firmware version, hardware version
- Serial number and UUID
- Hardware ID and authentication level

## Components

### `km003c-lib`
Core library providing:
- Device communication and automatic initialization
- Streaming authentication (required for AdcQueue)
- ADC and AdcQueue data parsing
- USB PD event parsing

### `km003c-cli`
Command-line tools:
- `adc_simple` - Single-shot ADC readings with device info
- `adc_queue_simple` - AdcQueue streaming demo
- `test_usbpd` - USB PD negotiation capture

### `km003c-egui`
GUI application featuring:
- Real-time voltage/current/power plots
- AdcQueue streaming with configurable sample rates
- Adjustable time window (2s to 5min or all data)
- Device info panel with auth status
- Connect/disconnect control

### Python Bindings
Python bindings for parsing KM003C data structures.

## Quick Start

### Prerequisites
- Rust 1.75+ (uses let-else and let-chains)
- USB access permissions (udev rules on Linux)
- POWER-Z KM003C device

### Installation
```bash
git clone https://github.com/okhsunrog/km003c-rs.git
cd km003c-rs
cargo build --release
```

### Linux USB Permissions

Create udev rules for non-root access:

```bash
sudo cp 71-powerz-km003c.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
sudo udevadm trigger
```

The rules use the `uaccess` tag for secure, dynamic access to logged-in users.

### Usage Examples

#### ADC Reading
```bash
cargo run --bin adc_simple
```

#### AdcQueue Streaming
```bash
cargo run --bin adc_queue_simple -- --rate 50 --duration 10
```

#### USB PD Capture
```bash
cargo run --bin test_usbpd
```

#### GUI Application
```bash
cargo run --bin km003c-egui
```

## Library Usage

```rust
use km003c_lib::{DeviceConfig, KM003C, GraphSampleRate};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect with vendor interface (Full mode - includes init and auth)
    let mut device = KM003C::new(DeviceConfig::vendor()).await?;

    // Access device info (always available in Full mode)
    let state = device.state().unwrap();
    println!("{}", state);  // Pretty-printed device info
    println!("AdcQueue enabled: {}", state.adcqueue_enabled);

    // Simple ADC reading
    let adc = device.request_adc_data().await?;
    println!("Voltage: {:.3} V", adc.vbus_v);
    println!("Current: {:.3} A", adc.ibus_a);

    // AdcQueue streaming (if authenticated)
    if device.adcqueue_enabled() {
        device.start_graph_mode(GraphSampleRate::Sps50).await?;
        // ... poll for samples ...
        device.stop_graph_mode().await?;
    }

    Ok(())
}
```

### Device Configuration

```rust
// Vendor interface (Full mode) - recommended, fastest
let config = DeviceConfig::vendor();

// HID interface (Basic mode) - most compatible, ADC/PD polling only
let config = DeviceConfig::hid();

// Skip USB reset (default on macOS for compatibility)
let config = DeviceConfig::vendor().skip_reset();
```

## Protocol Research

This implementation is based on reverse engineering documented at:
**[km003c-protocol-research](https://github.com/okhsunrog/km003c-protocol-research)**

The research repository contains:
- Complete protocol specification
- USB transport documentation
- PCAPNG captures and analysis tools
- Firmware analysis notes

## Development Status

### Working Features
- Device discovery and dual-interface communication
- Automatic initialization and streaming authentication
- Simple ADC measurements
- AdcQueue high-speed streaming (2-1000 SPS)
- USB PD message capture and parsing
- Memory read for device info/calibration
- Real-time GUI with plotting

### Tested Platforms
- Linux (primary development platform)
- macOS (uses `--no-reset` by default for compatibility)
- Windows (uses cross-platform `nusb`)

## Requirements

- **Rust**: 1.75+ (stable)
- **Platforms**: Linux, Windows, macOS
- **Hardware**: POWER-Z KM003C

## Contributing

Contributions welcome! See the research repository for protocol details.

## License

MIT License - see LICENSE file.

## Related Projects

- **[km003c-protocol-research](https://github.com/okhsunrog/km003c-protocol-research)** - Protocol reverse engineering
- **[usbpd](https://crates.io/crates/usbpd)** - Rust USB PD protocol library
