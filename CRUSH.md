# CRUSH Development Guidelines

## Build Commands
- `cargo build` - Build all packages in workspace
- `cargo build --release` - Build with optimizations
- `cargo build -p km003c-lib` - Build only library
- `cargo build -p km003c-cli` - Build only CLI tools
- `cargo build -p km003c-egui` - Build only GUI app

## Test Commands
- `cargo test` - Run all tests in workspace
- `cargo test -p km003c-lib` - Run only library tests
- `cargo test test_name` - Run specific test by name
- `cargo test module_name` - Run all tests in a module
- `cargo test --lib` - Run only library unit tests
- `cargo test --test integration_test_file` - Run specific integration test file

## Lint/Format Commands
- `cargo fmt` - Format all code according to rustfmt.toml (max_width = 120)
- `cargo fmt --check` - Check if code is formatted correctly
- `cargo clippy` - Run linting checks
- `cargo clippy --fix` - Automatically fix clippy issues

## Code Style Guidelines
- Use rustfmt for formatting (max_width = 120)
- Follow Rust naming conventions: snake_case for modules/variables/functions, CamelCase for types, SCREAMING_SNAKE_CASE for constants
- Use thiserror for custom error types
- Use tracing for structured logging
- Prefer async/await with tokio for asynchronous operations
- Use modular_bitfield for bitfield structs
- Use zerocopy for safe transmutation of raw data
- Use bytes crate for efficient data handling
- Follow existing patterns for USB communication with nusb

## Error Handling
- Use Result<T, KMError> for fallible operations
- Implement From trait for automatic error conversion
- Create specific error variants for different failure modes

## Imports
- Group imports logically (std, external crates, workspace crates, local modules)
- Use explicit imports rather than glob imports
- Follow alphabetical ordering within groups

## Types & Naming
- Use descriptive names that clearly indicate purpose
- Follow existing naming patterns in the codebase
- Use strong typing with enums and structs rather than primitives when possible