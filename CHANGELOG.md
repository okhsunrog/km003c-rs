# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- The release workflow builds `km003c` wheels for Linux, macOS and Windows on
  both x86-64 and arm64 plus a source distribution, and uploads them to PyPI
  through trusted publishing, so `pip install km003c` no longer requires a Rust
  toolchain. A manual run publishes only when asked for.

### Changed

- The Python extension is built against the stable ABI (`abi3-py38`). One wheel
  per platform now covers every CPython from 3.8 up, and a new interpreter
  release needs no rebuild.

## [0.4.0] - 2026-09-22

### Added

- `DeviceSelector` and `DeviceConfig::select()` open a specific KM003C by USB
  serial number or bus address. A USB reset now reopens the same unit instead
  of whichever KM003C the OS lists first.
- `PacketPeek` reads a framed response's type and transaction ID from the
  header bytes alone, without parsing the body.
- `Packet::find_payload()` for selecting a payload the typed accessors do not
  cover.
- `auth::MemoryReadConfirmation` and `auth::parse_memory_read_confirmation()`
  expose the confirmation layout that was previously private to the device
  layer.
- Python bindings for the authenticated commands, so host tooling no longer has
  to re-implement the AES keys, CRC layout and header framing:
  `build_memory_read_packet()`, `decrypt_memory_payload()`,
  `parse_memory_read_confirmation()`, `build_streaming_auth_packet()`,
  `parse_streaming_auth_response()`, `parse_log_metadata()` and
  `parse_offline_log_samples()`.
- Python constants for the USB interfaces/endpoints, the documented device
  memory map, `ATT_PD_TRACE`, `ATT_LOG_METADATA` and the PD-monitor,
  MemoryRead and StreamingAuth command codes.
- `PdTrace`, `PdTraceStateEvent`, `PdTraceProtocolEvent` and `LogMetadata` are
  registered with the Python module.

### Fixed

- `EnablePdMonitor` (0x10) and `DisablePdMonitor` (0x11) parsed back as
  `Packet::Generic`, so captures of the library's own traffic were left
  unclassified. Both now round-trip.
- `LogMetadata` was exposed to Python as a class with no readable attributes.
  It now has getters for every field.
- Every request parsed its response twice: once inside the correlation
  predicate and once for real. Correlation now peeks at the header instead of
  copying the transfer and allocating a `Vec` per logical packet.
- A short HardwareID read no longer authenticates with a zero-filled
  credential; it fails instead.
- `read_memory_block()` rejects a call made while AdcQueue streaming is active
  rather than consuming an in-flight response as ciphertext.
- GUI: the accepted forward sequence step is now derived from the configured
  rate. A stall longer than ~33 s at 2 SPS used to be classified as an
  out-of-order sample, after which every following sample was discarded until
  the counter wrapped. A run of rejected samples now restarts continuity.
- `AttributeSet::from_raw()` masks bit 15, which the 15-bit wire field cannot
  carry, and `AttributeSet::iter()` no longer scans it.
- `PdStatusRaw` re-encodes by rounding rather than truncating, matching
  `AdcDataRaw`.

### Changed

- `usbpd` comes from its 2.0.0 crates.io release instead of a git revision of a
  fork. The EPR and chunked-message work that revision carried was upstreamed
  and released, so the fork only held a pre-review snapshot of it. Published
  builds of `km003c-lib` already resolved `usbpd` from the registry, so this
  also removes a difference between what CI tested and what users got.
- **Breaking:** `Packet::GetData` carries an `attributes: AttributeSet` instead
  of `attribute_mask: u16`, and `Packet::StartGraph` carries a typed
  `rate: GraphSampleRate` instead of `rate_index: u16`. A `StartGraph` header
  with an undocumented rate index now parses as `Packet::Generic` rather than
  being coerced. The Python dictionary keys `attribute_mask` and `rate_index`
  are unchanged.
- **Breaking:** `RawPacket::validate_correlation()` takes an `AttributeSet`.
- **Breaking:** `PdEventData::Connect` and `PdEventData::Disconnect` are unit
  variants. In Python they were both indistinguishable from `None`; they are
  now `{"Connect": None}` and `{"Disconnect": None}`, and a PD message is
  `{"PdMessage": {"sop": ..., "wire_data": ...}}`.
- **Breaking:** `PdEventStream::pd_messages()` yields `&[u8]` instead of
  `&Vec<u8>`, `HardwareId::bytes` is private behind `as_bytes()`, and
  `DeviceConfig` is `Clone` rather than `Copy`.
- `auth::build_memory_read_packet()` and `auth::build_streaming_auth_packet()`
  delegate to `Packet::to_raw_packet()`, so the vendor header layout has one
  definition. The device layer no longer special-cases these two commands.
- `Settings` implements `Serialize`/`Deserialize` under the `serde` feature.

## [0.3.0] - 2026-07-22

### Added

- Shared stateful USB PD decoding, including chunked EPR messages.
- Typed offline-log catalogs and samples, including high-level encrypted
  downloads and final-accumulator validation.
- `offline-log` CLI with metadata inspection and CSV/JSON export.
- Explicit-rate AdcQueue decoding in Python through
  `AdcQueueRawData.decode()` and `parse_packet_with_graph_rate()`.
- Level-2 calibration authentication through
  `KM003C::authenticate_calibration()`.
- `AuthCredential` distinguishes the StreamingAuth credential from a device
  `HardwareId`.
- Lossless, CRC-validated, read-only Settings parsing with typed accessors for
  firmware-confirmed fields and `KM003C::request_settings()`.
- Typed firmware PD state traces, including confirmed Type-C and
  protocol-engine events.
- Configurable GUI plots for voltage, signed and absolute current/power,
  charge, energy, CC1/CC2, and D+/D-.
- GUI recording and plot-buffer export to Parquet or CSV, with missing-sample
  quality data and separate signed net and positive-throughput accumulators.
- A combined GUI timeline for wire-level USB PD messages and firmware state
  traces, with independent filters for both sources.
- GUI browsing, download, plotting, and Parquet/CSV export for recordings
  stored on the KM003C.

### Changed

- `Packet::StreamingAuth` and its Python dictionary representation now name
  their 12-byte value `credential` instead of incorrectly assuming it is
  always a HardwareID.
- Context-free AdcQueue parsing now returns `AdcQueueRawData`; use
  `decode(GraphSampleRate)` when the `StartGraph` rate is known.
- `AdcQueueData` stores its configured `rate`, and
  `has_dropped_samples()` uses that rate directly.
- `AdcDataSimple::sample_rate` is now `Option<SampleRate>` so unknown wire
  indices are not misreported as 2 SPS. The original index is available as
  `sample_rate_raw`.
- `KM003C::read_memory_block()` returns exactly the requested number of bytes
  instead of exposing AES block padding.
- The Python package version is derived from the Rust crate version.
- PD status and event measurements share one representation, and the stateful
  decoder resets negotiation state on connection changes.
- The GUI distinguishes signed charge/energy from positive transferred totals
  and excludes duplicate, stale, and invalid-sequence samples from integration.

### Fixed

- Multi-transfer and non-block-aligned memory reads.
- Lossless ADC and AdcQueue parsing, including marker, flags, and unknown rates.
- PD timestamps, connection-state resets, and connection-status stability.
- Semantic round-trips for authentication and protocol packets.
- StartGraph validation when StreamingAuth does not grant AdcQueue access.
- StreamingAuth response decoding now preserves firmware auth levels 0, 1,
  and 2 instead of treating the level field as a Boolean flag.
- Parsing of populated zero-count firmware trace responses.
- Debounced GUI Type-C connection state during attach and detach transitions.

### Removed

- `KM003C::receive_memory_read_data()` and the synthetic
  `Packet::MemoryReadResponse` variant. Use `KM003C::read_memory_block()` for
  correlated device reads, or `auth::decrypt_memory_read_response()` for
  captured ciphertext.

## [0.2.0] - 2026-07-19

### Added

- Type-safe `uom` quantities for measurements, timestamps, and sample rates.
- Correlated USB request/response handling and complete bulk-frame reads.
- Recorded-capture tests for ADC, AdcQueue, authentication, and PD events.
- Cross-platform CI, MSRV checks, and Python binding validation.
- A single Rust 1.97 minimum supported version for the workspace.

### Fixed

- Rate-dependent AdcQueue scaling for CC1, CC2, D+, and D- measurements.
- Streaming-rate reporting now uses the device sequence clock.
- Validation of memory-read confirmations and streaming-auth failures.
- Parsing of chained AdcQueue/PD responses and legacy PD connection events.

[Unreleased]: https://github.com/okhsunrog/km003c-rs/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/okhsunrog/km003c-rs/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/okhsunrog/km003c-rs/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/okhsunrog/km003c-rs/releases/tag/v0.2.0
