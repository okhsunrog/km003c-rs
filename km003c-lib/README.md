# km003c-lib

Async USB communication and protocol parsing for the ChargerLAB POWER-Z
KM003C USB-C power analyzer.

The crate supports single-shot ADC measurements, authenticated AdcQueue
streaming at 2/10/50/1000 SPS, USB Power Delivery event capture, device
information, and recorded-packet parsing. Physical measurements use
[`uom`](https://docs.rs/uom) quantities throughout the Rust API.

Offline recordings are exposed as a catalog of typed `LogMetadata` entries.
`KM003C::download_offline_log()` selects the correct flash offset, validates
the final charge and energy accumulators, and returns typed `uom` samples.

Enable the optional `usbpd` feature to turn captured PD wire frames into typed
USB PD messages. `PdSessionDecoder` retains Source Capabilities state for
subsequent Request messages and reassembles chunked EPR Source Capabilities.

```rust,no_run
use km003c_lib::uom::si::electric_potential::volt;
use km003c_lib::{DeviceConfig, KM003C};

# async fn read_voltage() -> Result<(), Box<dyn std::error::Error>> {
let mut device = KM003C::new(DeviceConfig::vendor()).await?;
let adc = device.request_adc_data().await?;
println!("VBUS: {:.3} V", adc.vbus.get::<volt>());
# Ok(())
# }
```

See the [project repository](https://github.com/okhsunrog/km003c-rs) for the
CLI tools, GUI monitor, USB permissions, Python bindings, and protocol
research links.

## License

Licensed under either the Apache License, Version 2.0 or the MIT license, at
your option.
