# km003c-lib

Async USB communication and protocol parsing for the ChargerLAB POWER-Z
KM003C USB-C power analyzer.

The crate supports single-shot ADC measurements, authenticated AdcQueue
streaming at 2/10/50/1000 SPS, USB Power Delivery event capture, device
information, and recorded-packet parsing. Physical measurements use
[`uom`](https://docs.rs/uom) quantities throughout the Rust API.

Offline recordings are exposed as a catalog of typed `LogMetadata` entries.
`KM003C::download_offline_log()` selects the correct flash offset, accepts a
final charge and energy within one sample interval of the last sample, and
returns typed `uom` samples.

Normal vendor initialization authenticates with the device HardwareID at
level 1. `KM003C::authenticate_calibration()` safely reads the firmware-selected
calibration credential and requests level 2 without writing device memory.
MemoryRead follows the encoding flag on each confirmation and requests at most
2528 bytes at a time. This handles plaintext short replies and avoids the mixed
encrypted/plaintext large responses in the inspected 2.0.5 firmware. Large
reads are assembled without exposing transport padding to callers.

`KM003C::request_settings()` validates both persisted settings-block checksums
and exposes only firmware-confirmed fields semantically. Unknown bytes remain
available through the lossless raw block accessors; the API does not provide
settings writes.

Enable the optional `usbpd` feature to turn captured PD wire frames into typed
USB PD messages. `PdSessionDecoder` retains Source Capabilities state for
subsequent Request messages and reassembles chunked EPR Source Capabilities.
Firmware Type-C and protocol-engine traces are available separately as a typed
`PdTrace` containing `PdTraceStateEvent` and `PdTraceProtocolEvent` values.
Unknown codes remain available losslessly for firmware variants that have not
yet been reverse engineered.

The optional `polars` feature records live measurements to Parquet or CSV on a
background thread through a crash-safe journal (`Recorder`,
`recover_interrupted`), exports downloaded offline logs, and converts
measurements and offline logs to polars `DataFrame`s. `read_recording` reads a
file back with the recording schema's types. Use the re-exported
`km003c_lib::polars`, whose version is part of this feature's API. The
`preferences` feature adds the settings the GUIs share, saved as JSON.

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

## Firmware maintenance

`km003c_lib::firmware` exposes package inspection, device checks, verified backups
and the complete installation sequence. Frontends supply backup storage and
consume typed progress events; the library owns APP/DFU transitions, transfer
deadlines and full installed-image verification. Callers must release any live
measurement session before opening firmware maintenance.

Enable `firmware-catalog` for official release descriptions and package downloads.
`FirmwareCatalogClient` uses native HTTPS or browser Fetch, trying the official
server before the archive. HTTP, parsing and validation failures trigger fallback
to the same version/date/size/CRC. Catalogs and downloads expose their source and
fallback reason. `FirmwareHttpTransport` supports custom adapters and offline tests;
`FirmwareCatalog` and `FirmwareRelease::validate_package` remain usable separately.

```no_run
# #[cfg(all(feature = "firmware-catalog", not(target_arch = "wasm32")))]
# async fn example() -> Result<(), Box<dyn std::error::Error>> {
use std::io::Write;
use km003c_lib::{DeviceSelector, firmware::{PreparedFirmwareUpdate, catalog::FirmwareCatalogClient}};

let client = FirmwareCatalogClient::new()?;
let download = client.download_selected("2.0.7").await?;
let (_, image) = download.into_parts();
let selected = DeviceSelector::SerialNumber("007965".into());
let prepared = PreparedFirmwareUpdate::prepare(image, selected, |_event| {}).await?;

// The frontend can present prepared.device(), prepared.image() and its backup.
// Calling install authorizes flash writes; storage must succeed first.
let result = prepared.install(|backup| async move {
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open("current-firmware.bin")?;
    file.write_all(backup.data())?;
    file.sync_all()?;
    Ok(())
}, |_event| {}).await?;
assert!(result.bytes_verified > 0);
# Ok(())
# }
```

The CLI is one consumer of this API. See the repository's firmware documentation
for protocol evidence, hardware-tested upgrade/downgrade results and remaining
validation limits.

## License

Licensed under either the Apache License, Version 2.0 or the MIT license, at
your option.
