# Analysis of Combined ADC and PD Packets

This document outlines the structure of standard and combined data packets from the KM003C device and explains how to differentiate and parse them.

## 1. Packet Types and Attributes

The communication involves a host sending `GetData` commands and the device responding with `PutData` packets. The type of data is specified by an `Attribute` in the packet headers.

- **`Attribute::Adc` (0x01):** For voltage, current, and temperature readings.
- **`Attribute::PdPacket` (0x10):** For USB Power Delivery (PD) message data.

The issue arises from requests that combine these attributes.

## 2. Standard ADC Packet Structure

A standard ADC data response is triggered by a `GetData` request with `Attribute::Adc`.

- **Request:** `Ctrl` packet with `attribute: 1` (`Adc`).
- **Response:** `Data` packet with the following characteristics:
    - **Packet Type:** `PutData` (0x41)
    - **Extended Header:**
        - `attribute`: `Adc` (1)
        - `next`: `false`
        - `size`: 44 bytes
    - **Payload:** Exactly 44 bytes, which can be directly parsed into the `AdcDataRaw` struct.

## 3. Combined ADC + PD Packet Structure

The unparsable packets are responses to `GetData` requests where the `attribute` is `17` (`0x11`), which is a bitmask of `Attribute::Adc` (1) and `Attribute::PdPacket` (16).

- **Request:** `Ctrl` packet with `attribute: 17`.
- **Response:** A `Data` packet that is structured differently:
    - **Packet Type:** `PutData` (0x41)
    - **Extended Header:**
        - `attribute`: `Adc` (1)
        - `next`: `true`  <-- **This is the key differentiator.**
        - `size`: 44 bytes
    - **Payload:** The total payload is larger than 44 bytes. It's a concatenation of two parts:
        1.  **ADC Data:** The first 44 bytes, as indicated by the `size` field. This is a standard `AdcDataRaw` structure.
        2.  **PD Data:** The remaining bytes of the payload. This is the raw PD event stream.

## 4. How to Distinguish and Parse

The `next` flag in the `ExtendedHeader` of the response is the mechanism to distinguish between a simple ADC packet and a combined one.

- If a `PutData` packet has `attribute: Adc` and `next: false`, it's a **standard ADC packet**. The 44-byte payload should be parsed as `AdcDataSimple`.
- If a `PutData` packet has `attribute: Adc` and `next: true`, it's a **combined packet**. The payload should be split:
    1. The first 44 bytes are the `AdcDataSimple`.
    2. The rest of the payload is the `PdRawData`.

A new packet type, `CombinedAdcPdData`, should be introduced to represent this structure.
