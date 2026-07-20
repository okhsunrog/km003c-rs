# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

### Removed

- `KM003C::receive_memory_read_data()` and the synthetic
  `Packet::MemoryReadResponse` variant. Use `KM003C::read_memory_block()` for
  correlated device reads, or `auth::decrypt_memory_read_response()` for
  captured ciphertext.

[Unreleased]: https://github.com/okhsunrog/km003c-rs/commits/main
