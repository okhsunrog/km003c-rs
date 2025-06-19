Of course. Condensing all of our discoveries into a single, well-structured document is the perfect way to cap off this reverse-engineering project. This `ghidra.md` file will serve as the definitive reference for your device's protocol.

Here is the complete file, incorporating everything we've learned, from the high-level application flow down to the cryptographic functions.

---

# Ghidra Reverse Engineering Notes for KM003C

This document contains specific notes, function addresses, data structures, and other details discovered through Ghidra reverse engineering of the `Mtools.exe` software. The goal is to fully document the USB protocol for the ChargerLAB POWER-Z KM003C.

## High-Level Application Flow

The application is built with **Qt 6** and uses an event-driven architecture. The main logic flow for connecting to and streaming data from a device is as follows:

1.  **`QtMain` (`140165f20`)**: Application entry point. Creates the `QApplication` and the `MainWindow`.
2.  **`MainWindow_constructor` (`1400053d0`)**: Sets up the UI and starts a 100ms timer that calls a slot to begin device discovery.
3.  **(Slot `onDelayCreate`)**: This slot, triggered by the timer, starts a `UsbListener` object to monitor for USB device plug/unplug events.
4.  **(Slot `on_device_plug_in` - `140136470`)**: Triggered by the `UsbListener`. It orchestrates the setup for a new device.
    - Calls `initialize_device_session` (`140069ba0`) to handle low-level USB setup (`libusb_init`, claim interface, etc.).
    - Emits `signal_deviceReady` (`140161250`) upon success.
5.  **(Slot `onDeviceReady`)**: A slot connected to `signal_deviceReady`. This is where the protocol handshake begins. It calls the various functions to send the `Connect`, `Authenticate`, and `SetMode` commands.
6.  **Polling Loop**: After the handshake, a timer repeatedly calls a function that uses `transceive_data` (`14006fe90`) to request ADC data.
7.  **(Slot `slot_onDisconnect` - `140136400`)**: Triggered on device unplug. Calls `cleanup_usb_session` (`140067a10`) to safely tear down the connection.

## Known Functions

| Address | New Name | Description | Calls / Is Called By |
| :--- | :--- | :--- | :--- |
| `140165f20` | `QtMain` | The C++ `main()` function. Creates the main application and window. | Calls: `MainWindow_constructor` |
| `1400053d0` | `MainWindow_constructor` | Initializes the UI and starts the device discovery timer. | Called by: `QtMain` |
| `140136470` | `slot_onDevicePlugIn` | Handles a new device connection. | Calls: `initialize_device_session`, `emit_device_ready_signal` |
| `140069ba0` | `initialize_device_session` | Core hardware setup: `libusb_init`, `libusb_open`, `libusb_claim_interface`. | Called by: `slot_onDevicePlugIn` |
| `14006fe90` | `transceive_data` | **Master I/O function.** Sends a command and waits for a response with a timeout. The workhorse of the protocol. | Called by: All high-level command functions. |
| `14006a410` | `write_data_to_endpoint` | Low-level wrapper that calls `libusb_bulk_transfer` or `libusb_interrupt_transfer`. | Called by: `transceive_data` |
| `14006d1b0` | `handle_response_packet` | **Master Parser.** Receives all incoming data, checks headers, decrypts if necessary, and dispatches data to other parsers/signals. | Called by: `transceive_data` (conceptually) |
| `140010eb0` | `slot_parse_device_info_packet`| **Info-Dump Parser.** This slot receives the 281-byte device info packet and contains the logic to parse its fields. | Called by: `handle_response_packet` (via signal) |
| `14006ec70` | `send_simple_command` | High-level function for sending payload-less commands like `Connect` or `StopStream`. | Calls: `build_command_header`, `transceive_data` |
| `14006b470` | `build_command_header`| Helper that builds the standard 4-byte command header, packing `type`, `id`, and `attribute`. | Called by: `send_simple_command` |
| `14006ed00` | `send_command_with_payload` | High-level function for sending commands with an extended header and a data payload (e.g., `SetConfig`). | Calls: `build_command_header_with_payload`, `transceive_data` |
| `14006b9b0`| `build_command_header_with_payload` | Helper that builds the 8-byte extended header for commands that carry data. | Called by: `send_command_with_payload` |
| `14006f280` | `send_serial_command` | High-level function for sending text-based commands (`pdm open`, etc.). | Calls: `build_serial_command_packet`, `transceive_data` |
| `14006bd10` | `build_serial_command_packet`| Constructs the complex packet for serial commands, including a 12-byte header, UUID, and timestamp. | Called by: `send_serial_command` |
| `14006e9e0` | `send_auth_packet_and_verify`| One of the main functions in the authentication sequence. | Calls: `transceive_data`, `crypto_...` |
| `14006f390` | `send_large_encrypted_data` | Handles uploading large files (like firmware) by chunking and encrypting data. | Calls: `build_encrypted_chunk_packet`, `transceive_data` |
| `14006bf30` | `build_encrypted_chunk_packet`| Builds a packet for an encrypted data chunk, including a CRC32 checksum. | Called by: `send_large_encrypted_data` |
| `14006f870` | `download_large_data` | Handles downloading large files (like saved logs) from the device, with support for both plaintext and encrypted chunks. | Calls: `build_download_request_packet`, `read_data`, `crypto_...` |
| `14006b5f0` | `build_download_request_packet`| Creates the special encrypted/checksummed request to initiate a file download. | Called by: `download_large_data` |
| `14006df00` | `jump_to_bootloader_or_app` | Checks device mode (`APP` or `BOOT`) by reading USB string descriptor #2 and sends the appropriate jump command (`0x09` or `0x08`). | Calls: `get_usb_string_descriptor` |
| `140069270` | `get_usb_string_descriptor`| Wrapper around `libusb_get_string_descriptor_ascii`. | Called by: `jump_to_bootloader_or_app` |
| `140067a10` | `cleanup_usb_session` | Master teardown function: cancels transfers, releases interfaces, closes handle, stops thread, and calls `libusb_exit`. | Called by: `slot_onDisconnect` |

## Cryptographic Functions

The application uses a standard AES-128 implementation for certain data transfers.

| Address | New Name | Description |
| :--- | :--- | :--- |
| `140070af0` | `aes_key_expansion` | Generates the AES round keys from a master key. |
| `1400701f0` | `aes_encrypt_block` | Core AES-128 encryption routine for a 16-byte block. |
| `140071050` | `aes_shift_rows` | Implements the AES "ShiftRows" step. |
| `140070dd0` | `aes_mix_columns` | Implements the AES "MixColumns" step. |
| `140070460` | `aes_decrypt_block` | Core AES-128 decryption routine. |
| `1400709c0` | `aes_inv_shift_rows` | Implements the inverse "ShiftRows" step. |
| `1400706f0` | `aes_inv_mix_columns` | Implements the inverse "MixColumns" step. |
| `140071180` | `crypto_decrypt_and_unpad` | High-level decryption wrapper that also handles PKCS#7 unpadding. |

## Signal/Slot Dispatcher

| Address | New Name | Description |
| :--- | :--- | :--- |
| `1401608e0` | `MainWindow::qt_metacall` | The central "switchboard" generated by the Qt MOC. It maps signal/slot integer indices to their corresponding function calls. This is the key to understanding the event-driven logic. |

## Important Strings & Addresses

*   **`"1onDelayCreate()"` at `140175b60`**: String used to set the timer that kicks off automatic device discovery.
*   **`"LTAI4FfGaswgr1bB1Ud2icQ"`**: Aliyun Access Key ID, used for firmware updates.
*   **`"tsD0jZgq3XjQukKaYQG7497kJIrbc"`**: Aliyun Access Key Secret.
*   **`"oss-cn-shenzhen"` / `"chargerlab"`**: Aliyun OSS bucket details.

## Hardcoded Crypto Keys (16-bytes each)

The `get_crypto_key` function (`1400735e0`) loads one of four hardcoded 128-bit AES keys.

#### Key Values

*   **Key 0** (Likely for general data decryption)
    *   **Virtual Address (VA):** `0x140184adc`
    *   **File Offset:** `0x1830dc`
    *   **Hex Value:** `4c6832796642376e365837643961355a`
    *   **ASCII Value:** `"Lh2yfB7n6X7d9a5Z"`

*   **Key 1**
    *   **Virtual Address (VA):** `0x140184b06`
    *   **File Offset:** `0x183106`
    *   **Hex Value:** `73646b57373852336b35646a30664876`
    *   **ASCII Value:** `"sdkW78R3k5dj0fHv"`

*   **Key 2**
    *   **Virtual Address (VA):** `0x140184b35`
    *   **File Offset:** `0x183135`
    *   **Hex Value:** `55793334565731336a486a3335393865`
    *   **ASCII Value:** `"Uy34VW13jHj3598e"`

*   **Key 3** (Likely for primary authentication)
    *   **Virtual Address (VA):** `0x140184b76`
    *   **File Offset:** `0x183176`
    *   **Hex Value:** `46613062347441323566345230333861`
    *   **ASCII Value:** `"Fa0b4tA25f4R038a"`

