# MemoryRead APP replay fixtures

These are synthetic wire responses produced by executing the original Cortex-M
Thumb MemoryRead handlers in Unicorn 2.1.4. They are not device captures.
The source manufacturer packages are archived in
[km003c-resources](https://github.com/okhsunrog/km003c-resources).
`provenance.json` records the exact package and decrypted-image SHA-256 hashes.
Images load at 0x4000; no physical USB device is opened.

| Version | Handler runtime address | Header word | Full 2544-byte blocks | Remainder |
| --- | --- | --- | --- | --- |
| 1.9.9 | 0x46cac | 0x0101 | AES | AES |
| 2.0.5 | 0x45514 | 0x0100 | AES | Plaintext |
| 2.0.6 | 0x45524 | 0x0101 | AES | AES |
| 2.0.7 | 0x455bc | 0x0101 | AES | AES |

The emulator maps each image as executable memory and calls the actual handler.
Mutex and delay services return immediately. The AES service uses the existing
library MemoryRead key in software, while USB sends are collected as bytes.
This verifies control flow and byte transformations, not peripheral behavior,
USB timing or compatibility with other builds/hardware.

The source memory starts at 0x20020000 and contains the deterministic pattern
`byte[i] = (i * 17 + 23) % 256`. Request checksums are obtained through the
library's existing MemoryRead request builder.

- `VERSION-header.bin` and `VERSION-data.bin`: a 12-byte request, transaction
  ID 42, followed by 16 transport bytes. The library must remove padding and
  decode according to that confirmation's flag.
- `2.0.5-large-*`: one 2544-byte request, ID 42. The header claims plaintext
  although the entire data block is encrypted. The decoder must reject this
  unsafe response; normal reads avoid requesting such a block.
- `VERSION-8336.bin`: four successive requests of 2528, 2528, 2528 and 752
  bytes, with contiguous source addresses and transaction IDs 42 through 45.
  Each request contributes a 20-byte confirmation followed by its complete
  transport data. The expected result is the first 8336 source-pattern bytes.

Only synthetic responses and provenance are stored here, not manufacturer
executables or decrypted firmware images.
