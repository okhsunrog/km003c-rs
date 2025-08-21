# Verification Plan for PD and ADC Data Parsing

This document outlines the plan for verifying the correctness of the Power Delivery (PD) and Analog-to-Digital Converter (ADC) data parsing logic in the `km003c-lib` library. The verification will be performed by comparing the data from a Wireshark capture (`.pcapng`) with the data from an SQLite database (`.sqlite`) exported from the official POWER-Z application, both from the same capture session.

## Verification Goals

The primary goal is to ensure that the data parsed from the `.pcapng` file by our library matches the data exported by the official application into the `.sqlite` file. This will provide a high level of confidence that our reverse-engineered protocol and parsing logic are correct.

## Verification Steps

### 1. Power Delivery (PD) Data Verification

#### 1.1. Data Extraction

- **From `.pcapng` file:** The `analyze_pd_packets.rs` example will be used to parse the `.pcapng` file. This example identifies `PutData` packets with the `PdPacket` attribute and extracts the "inner event stream" from their payload. This raw event stream will be saved for comparison.

- **From `.sqlite` file:** The `sqlite_pd.rs` example will be used to read the `pd_table` from the `.sqlite` file. The `Raw` column of this table contains the "inner event stream" as a `BLOB`. This data will also be saved for comparison.

#### 1.2. Comparison

A byte-for-byte comparison of the extracted "inner event stream" data from both sources will be performed. The timestamps from both sources should also be compared to ensure that the packets are aligned correctly.

### 2. Analog-to-Digital Converter (ADC) Data Verification

#### 2.1. Data Extraction

- **From `.pcapng` file:** A modified version of the `analyze_pd_packets.rs` example will be used to parse `PutData` packets with the `Adc` attribute. The raw ADC data will be parsed into `AdcDataSimple` structs, and the relevant fields (`VBUS`, `IBUS`, `CC1`, `CC2`) will be extracted.

- **From `.sqlite` file:** The `sqlite_pd.rs` example will be used to read the `pd_chart` table from the `.sqlite` file. The `VBUS`, `IBUS`, `CC1`, and `CC2` columns will be extracted.

#### 2.2. Comparison

The ADC values from both sources will be compared. It is expected that there might be minor differences due to floating-point precision, so the comparison should be done with a small tolerance.

## Required Tools

- **`analyze_pd_packets.rs` example:** To parse the `.pcapng` file.
- **`sqlite_pd.rs` example:** To read the `.sqlite` file.
- **A new, combined verification tool:** To automate the comparison process, a new example could be created that reads both files, performs the comparisons, and reports any discrepancies.

## Expected Outcome

The expected outcome is that the data from both the `.pcapng` and `.sqlite` files will match, within the acceptable tolerance for floating-point values. A successful match will validate our understanding of the protocol and the correctness of our parsing implementation.
