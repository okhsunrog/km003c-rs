set shell := ["bash", "-euo", "pipefail", "-c"]

default:
    @just --list

# Format all Rust sources.
fmt:
    cargo fmt --all

# Verify formatting without changing files.
fmt-check:
    cargo fmt --all -- --check

# Type-check every workspace target and feature.
check:
    cargo check --workspace --all-targets --all-features --locked

# Run the offline test suite, including recorded protocol captures.
test:
    cargo test --workspace --all-targets --all-features --locked

# Treat every Clippy warning as an error.
lint:
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

# Build API documentation with warnings denied.
doc:
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked

# Verify the publishable library crate contents.
package:
    cargo package -p km003c-lib --locked

# Build and test the Python extension in the uv environment.
python-test:
    uv sync --locked
    uv run maturin develop
    uv run pytest -q test_bindings.py

# Full offline pre-push gate. Hardware is intentionally excluded.
ci: fmt-check test lint doc package python-test

# Read one ADC sample from a connected KM003C.
hardware-adc:
    cargo run -p km003c-cli --bin adc_simple

# Stream from a connected KM003C at RATE SPS for DURATION seconds.
hardware-stream rate="50" duration="10":
    cargo run -p km003c-cli --bin adc_queue_simple -- --rate {{rate}} --duration {{duration}}

# Capture USB Power Delivery traffic from a connected KM003C.
hardware-pd:
    cargo run -p km003c-cli --bin test_usbpd

# Start the graphical monitor.
gui:
    cargo run -p km003c-egui
