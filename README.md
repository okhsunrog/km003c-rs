# km003c-rs

Rust library and applications for the **ChargerLAB POWER-Z KM003C** USB-C power analyzer.

## Overview

`km003c-rs` provides a cross-platform Rust implementation for communicating with the KM003C device, enabling real-time USB-C power analysis and USB Power Delivery message capture.

## Features

### 🔌 Device Communication
- USB HID communication (VID: 0x5FC9, PID: 0x0063)
- Cross-platform support using `nusb`
- Asynchronous communication with Tokio
- Automatic device discovery and connection management

### 📊 ADC Data Acquisition
- Real-time voltage, current, and power measurements
- Multiple sample rates (1, 10, 50, 1000, 10000 SPS)
- Temperature monitoring
- USB data line voltage measurements (D+, D-)
- USB CC line voltage measurements (CC1, CC2)

### ⚡ USB Power Delivery Support
- Capture and parse USB PD messages
- Connection event detection
- Full PD message parsing using the `usbpd` crate
- Support for source capabilities and control messages

## Components

### `km003c-lib`
Core library providing device communication and data parsing.

### `km003c-cli`
Command-line tools:
- `adc_simple` - Basic ADC data reading
- `pd_monitor` - Real-time PD message monitoring

### `km003c-egui`
GUI application with real-time plotting and live status display.

### Python Bindings
Python bindings for parsing KM003C data structures (no async device communication).

## Quick Start

### Prerequisites
- Rust 1.89 or newer
- USB access permissions (udev rules on Linux)
- POWER-Z KM003C device

### Installation
```bash
git clone https://github.com/okhsunrog/km003c-rs.git
cd km003c-rs
cargo build --release
```

### Linux USB Permissions

On Linux, you need to set up udev rules to allow non-root access to the device:

```bash
sudo cp 71-powerz-km003c.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
sudo udevadm trigger
```

**Note:** The udev rules use the modern `uaccess` tag approach recommended for systemd systems. This provides secure, dynamic access to logged-in users without requiring overly permissive modes or group membership. The file is numbered `71-*` to ensure it's processed before systemd's `73-seat-late.rules`. See the [Arch Wiki on udev](https://wiki.archlinux.org/title/Udev#Allowing_regular_users_to_use_devices) for more details.

### Usage Examples

#### ADC Reading
```bash
cargo run --bin adc_simple
```

#### PD Message Monitoring
```bash
cargo run --bin pd_monitor --frequency 1.0
```

#### GUI Application
```bash
cargo run --bin km003c-egui
```

#### Python Bindings
```bash
# Install in development mode
uv run maturin develop

# Use the bindings
python -c "
import km003c
print(f'KM003C VID: {hex(km003c.VID)}, PID: {hex(km003c.PID)}')
rates = km003c.get_sample_rates()
print(f'Available sample rates: {[rate.name for rate in rates]}')
"
```

## Library Usage

```rust
use km003c_lib::KM003C;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut device = KM003C::new().await?;
    
    // Read ADC data
    let adc_data = device.request_adc_data().await?;
    println!("Voltage: {:.3} V", adc_data.vbus_v);
    println!("Current: {:.3} A", adc_data.ibus_a);
    
    // Read PD data
    let pd_data = device.request_pd_data().await?;
    // Process PD messages...
    
    Ok(())
}
```

## Protocol Research

This implementation is based on reverse engineering research documented at:
**[km003c-protocol-research](https://github.com/okhsunrog/km003c-protocol-research)**

The research repository contains:
- Complete protocol documentation
- PCAPNG captures and analysis
- Python analysis tools
- Reverse engineering methodology

## Development Status

### ✅ Working Features
- Device communication and data acquisition
- ADC measurements with all supported sample rates
- USB PD message capture and parsing
- Real-time GUI with plotting
- Command-line monitoring tools

### 🔄 In Progress
- Additional device commands
- Enhanced error handling
- Performance optimizations

## Requirements

- **Rust**: 1.89+
- **Dependencies**: See `Cargo.toml` files
- **Platforms**: Linux, Windows, macOS
- **Hardware**: POWER-Z KM003C device

## Contributing

Contributions are welcome! Please see the research repository for protocol details and reverse engineering findings.

## License

MIT License - see LICENSE file for details.

## Related Projects

- **[km003c-protocol-research](https://github.com/okhsunrog/km003c-protocol-research)** - Protocol reverse engineering
- **[usbpdpy](https://github.com/okhsunrog/usbpdpy)** - Python bindings for USB PD parsing
- **[usbpd](https://crates.io/crates/usbpd)** - Rust USB PD protocol library

---

**For protocol research and analysis tools, visit: [km003c-protocol-research](https://github.com/okhsunrog/km003c-protocol-research)**