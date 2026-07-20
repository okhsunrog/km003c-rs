# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Shared stateful USB PD decoding, including chunked EPR messages.
- Typed `LogMetadata` attribute support in the protocol header layer.
- Explicit-rate AdcQueue decoding in Python through
  `AdcQueueRawData.decode()` and `parse_packet_with_graph_rate()`.

### Changed

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

### Fixed

- Multi-transfer and non-block-aligned memory reads.
- Lossless ADC and AdcQueue parsing, including marker, flags, and unknown rates.
- PD timestamps, connection-state resets, and connection-status stability.
- Semantic round-trips for authentication and protocol packets.
- StartGraph validation when StreamingAuth does not grant AdcQueue access.

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

[Unreleased]: https://github.com/okhsunrog/km003c-rs/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/okhsunrog/km003c-rs/releases/tag/v0.2.0
