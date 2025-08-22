# Examples

This directory contains a collection of examples that demonstrate how to use the `km003c-lib` library. These examples are also used for reverse engineering and analyzing the protocol.

## Running the Examples

To run an example, use the following command:

```sh
cargo run --example <example_name>
```

For example, to run the `sqlite_pd` example, you would use:

```sh
cargo run --example sqlite_pd
```

## Example Descriptions

- **`analyze_parquet.rs`**: Inspects the contents of a `.parquet` file created by `process_pcapng.rs`.
- **`analyze_pd_packets.rs`**: Parses and analyzes Power Delivery (PD) packets from a `.pcapng` file. This example has a `--verbose` flag to print more detailed information.
- **`parse_tshark.rs`**: A basic example that demonstrates how to parse a `.pcapng` file using `rtshark` and the `km003c-lib`.
- **`print_pd_samples.rs`**: Collects and prints unique samples of different PD packet types from a `.pcapng` file.
- **`process_pcapng.rs`**: Processes a `.pcapng` file and saves the extracted data to a `.parquet` file.
- **`sqlite_pd.rs`**: Reads and parses PD data from a `pd_new.sqlite` database file.
- **`summarize_parquet.rs`**: Prints a summary of the data contained in a `.parquet` file.
- **`pcap_to_csv.rs`**: Logs USB packets from a `.pcapng` file to CSV and Markdown, with optional filters.
