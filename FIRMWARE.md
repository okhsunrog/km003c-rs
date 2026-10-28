# Firmware support

Firmware installation is experimental. The implementation combines the package
work contributed in [PR #60](https://github.com/okhsunrog/km003c-rs/pull/60/changes/561733c8a18244fbfc8afd7a1f7539587e1eff8c),
an independently decoded successful update capture, official Mtools.exe 2.5.2
decompilation, and a repeatable read of the connected meter's bootloader.

## GUI installation

The egui monitor has a **Firmware** tab for desktop and browser use. Refresh the
catalog and download a specific version/date/build, or open a local `.mencrypt`
package. Older and same-version builds use the same installation flow as upgrades.
The package identity, size, CRC and release notes are shown before device access.

**Check meter** disconnects measurement acquisition and waits for its USB handle
to be released before checking the selected meter. **Review installation** shows
the meter identity and current/target builds; installation requires a separate
confirmation and a backup destination. A recording or offline transfer must finish
first. Automatic reconnection stays disabled until the user presses **Start**.

The UI forwards library progress through backup, erase, transfer and complete
readback verification. It prevents normal window closing during installation.
Desktop backups are created without overwriting existing files and flushed before
flash operations. Browser backups require the File System Access API: the file's
write and close operations must complete before erasure, rather than relying on a
download notification. Use **Authorize meter** to grant WebUSB permission; a meter
that reappears in DFU may need permission again before retrying recovery.

The GUI adapter is covered by offline state/rendering/storage tests and native/Wasm
builds. Device tests of the GUI installation flow remain pending; CLI hardware
results do not establish browser dialog or WebUSB re-enumeration behavior.

## Shared library API

The complete maintenance flow belongs to `km003c-lib::firmware`. CLI code only
parses arguments, formats results/progress and saves bytes to files.

- `FirmwareImage`: immutable package parsing and validation.
- `check_firmware_device`: typed USB mode, hardware and installed-firmware
  information without reboot or flash writes.
- `PreparedFirmwareUpdate::prepare`: pin one device and acquire a verified
  application backup through two matching reads, application vectors, embedded
  identity and normalized image CRC.
- `PreparedFirmwareUpdate::install`: invoke the frontend's asynchronous backup
  storage callback, switch APP/DFU modes, transfer, restart and compare the full
  installed application. A storage failure aborts before reboot or erase.
- `FirmwareInstallProgress` / `FirmwareInstallResult`: shared frontend events
  and the verified installation result; no terminal output or file paths.
- With `firmware-catalog`: `FirmwareCatalog`, `FirmwareRelease` and
  `FirmwareDownload` provide typed catalog/package data and validation.
  Native and browser frontends use `FirmwareCatalogClient::fetch/download`
  for official-first HTTP with validated archive fallback. Basic USB users do
  not need the firmware HTTP dependencies.

GUI frontends can save a `FirmwareBackup` using their own storage mechanism and
forward progress to the UI. They do not need to reproduce protocol, backup or
verification decisions. A live measurement session must release its USB handle
before maintenance begins. Catalog parsing, request signing, source selection
and package validation also compile for Wasm. Browser frontends use the same
client through Fetch. Custom adapters can
implement `FirmwareHttpTransport` without reproducing fallback policy.

## Package validation

Application backup validation uses the installed metadata's size, identity and
CRC. The bootloader changes offsets 0x428..0x430 only after verifying the original
image, so those eight bytes are treated as 0xff when checking the stored CRC.
This check runs during preparation, before backup storage, DFU or flash writes;
two equal responses alone do not establish that a backup is correctly decoded.

`.mencrypt` contains ten Qt big-endian QString fields followed by one QByteArray:
format labels, model, version, build date, hexadecimal CRC32, plaintext size,
Chinese release notes and English release notes, followed by encrypted firmware.
The payload uses AES-128-ECB with the device memory-read key. Keep the original
ciphertext and exclude outer file trailers from the upload. A verified 1.9.9
package has four such trailer bytes; the independently downloaded 2.0.7 package
does not. This does not establish a package-format revision.

`FirmwareImage` is immutable after parsing. Update validation checks the CRC,
application vectors, base address, model/version/date against their embedded
copies, and erased size/CRC placeholders. The inspected bootloader accepts
application sizes up to `0x6fffe`. The normal updater always uses base `0x4000`.

## MemoryRead compatibility

The response confirmation's byte 2 bit 0 describes its encoding; the other
skipped header bits are not the object count or an attribute selector.
The inspected APP images behave as follows:

| Image | Runtime MemoryRead handler | Flag | Full 2544-byte blocks | Remainder |
| --- | --- | --- | --- | --- |
| 1.9.9 (2025.9.22, package SHA256 prefix cdbdd032c49f) | 0x46cac | 1 | AES | AES |
| 2.0.5 (2026.7.15) | 0x45514 | 0 | AES | Plaintext |
| 2.0.6 (2026.8.9) | 0x45524 | 1 | AES | AES |
| 2.0.7 (2026.9.29) | 0x455bc | 1 | AES | AES |

On 2.0.5, the flag does not describe the entire large response. Reading 2544
bytes yields ciphertext with a plaintext flag; reading 2545 yields 2544
encrypted bytes followed by a 16-byte padded plaintext remainder. Both always
decrypting and always trusting flag zero for the whole large reply are wrong.

The library issues requests of at most 0x9e0 (2528) bytes, below the problematic
0x9f0 boundary, and validates and decodes every confirmation independently.
The caller receives exactly its requested bytes after each response's padding
is removed. Request ranges include transport padding in overflow checks, and
the existing firmware limit of 4,000,000 bytes is preserved for a composed read.
There is no heuristic based on whether bytes look like readable metadata.

The [replay fixtures](km003c-lib/tests/fixtures/memory_read/README.md) record
responses from the original Thumb handlers executed in Unicorn, with modeled
AES/USB services. Unit tests replay 12-byte initialization reads, the unsafe
2.0.5 boundary reply and composed 8336-byte reads for all four images. Scripted
transport tests also cover flag changes, id wrap, padding, invalid confirmations
and transfer failures. These are offline checks; real-device timing and other
builds/hardware revisions still need validation.

## Public firmware archive

The fallback archive catalog is
[`km003c-resources/catalog.json`](https://okhsunrog.github.io/km003c-resources/catalog.json).
Packages are served from the same Pages origin without authorization. The client
first tries the official server for catalogs and downloads. HTTP, CORS, parse,
checksum or identity errors trigger archive fallback. Matching requires version,
date, application size and CRC; unavailable exact matches fail rather than
substituting another build. Mirror-selected builds retain their whole-file SHA256
even if an official object is available. Catalogs and downloads expose `source()`
and `fallback_reason()` for presentation and diagnostics.
The publisher validates packages with this library and preserves original bytes.
Windows applications, manuals and complete source archives are
[Release assets](https://github.com/okhsunrog/km003c-resources/releases).
The `orig_app` directory was already absent from the current source tree;
complete historical snapshots are now in the resource archive. Git history has
not been rewritten to move those files.

The version-1 JSON catalog records model, version, build date, full package hash
and size, firmware CRC and size, both release-note languages and provenance.
Downloads validate the whole package SHA-256 (including outer trailers) before
checking firmware CRC and identity. Paths are restricted to this mirror and
derived from metadata plus the full hash; arbitrary URLs and redirects are rejected.

A version is not a unique build selector. The archive file named
`KM003C_V2.0.0.mencrypt` identifies itself as 2.0.1 (2026.4.9), while another
2.0.1 is dated 2026.4.21. `select_release` accepts a unique version or a build ID;
an ambiguous version reports the available IDs instead of picking the first.
Neither latest nor stable status is inferred from the largest version number.

## Official catalog backend

The official backend is the primary source on native and browser targets. On
2026-10-28 the bundled credential initially returned `403 InvalidAccessKeyId`
with a disabled-key message; later the identical pair successfully fetched the
catalog and 2.0.7 package with HTTP 200. The cause of the status change is unknown.
Credentials stay encrypted in the library and decode lazily; no official EXE
is needed. Network rechecks do not access the USB device.

The official backend reads `expect.xml` and firmware objects from:

```text
https://product-km003c.oss-cn-hangzhou.aliyuncs.com/
```

Official EXE functions establishing the route in the independently analyzed
build (SHA256 `0780669c5f7ac3d846ae7be2ea5f0fc306f2e542af457e93264b88ce4bf65666`):

| Function | Observed behavior |
|---|---|
| `0x1400beb10` | Initializes shared OSS credentials, `product-<model>` bucket and Hangzhou region |
| `0x140295a30` | Normalizes bucket name to lowercase, replaces spaces/underscores with hyphens |
| `0x1400bf260` | Reads cached `expect.xml` or requests that object |
| `0x14018adf0` | Refreshes the local catalog and processes its XML |
| `0x1400bf630` | Parses `Updateinfo`, versions, object keys and release descriptions |
| `0x140291940` | Downloads an object through `QNetworkAccessManager::get` |
| `0x140297270` | Builds the GET request and signed resource |

The feed contains `DeviceName` and repeated `Title version="..."` elements.
Fields include `Key`, `Url`, `LastModified`, `ETag`, `Crc`, `Size`, `Note`,
`Note2`, `IsLatest` and `IsStable`. `Note` is Chinese; `Note2` is English.
The observed `Url` fields are placeholders; downloads use `Key` in the fixed
bucket. On 2026-10-28 the feed listed 31 releases from 1.5.1 alpha to 2.0.7.
All `IsLatest` flags were false, so the CLI requires an explicit version rather
than inferring one from that flag. Older releases remain available.

Anonymous GET returned 403; an OSS V1 signed GET returned 200. Shared access
credentials from the official application are included in the client. Native requests
use the [documented OSS V1 header signature](https://www.alibabacloud.com/help/en/oss/developer-reference/include-signatures-in-the-authorization-header):
HMAC-SHA1 over method, content headers, Date and canonical bucket/object path,
then Base64 in `Authorization`. Browser Fetch uses the corresponding
[OSS V1 signed URL](https://www.alibabacloud.com/help/en/oss/developer-reference/ddd-signatures-to-urls),
with a five-minute expiry instead of a Date header. Browser failures, including
missing CORS permission, follow the same archive fallback policy. Signed URLs
and authorization values are excluded from adapter error messages.
The implementation uses HTTPS, disables
redirects, bounds response size, masks authorization values in debug output,
and never performs bucket listing or write operations.

Downloaded packages must match the catalog's model, version, date, plaintext
size and CRC. `.mencrypt` CRC validates integrity; it is not a digital signature.
The downloaded 2.0.7 package had SHA256
`7a081af887fa8873d9e0cfc9cee9654187ab392f882efed16c1904a184ce8454`,
matching the image identified by the contributor.

The 1.9.9 object exposed a real catalog inconsistency during hardware testing:
the catalog described the 2025.9.22 build (453828 bytes, CRC `7C80B54E`), while
the server returned a 2025.10.13 build (454156 bytes, CRC `B8F0B468`). Both
packages' CRCs independently match their own plaintext sizes, excluding AES
padding. Their plaintext differs beyond the metadata, starting at offset
`0x634`; the larger byte difference also includes possible code relocations.
The CLI rejects this mismatch and reports the expected and received identities.
An identical version string is not sufficient to identify an image.

## Bootloader transfer

1. Select exactly one KM003C and pin its physical USB port (serial fallback).
2. In APP mode, read identity and preserve the installed application before reboot.
3. Send JumpDfu `0x09`, reopen the same device in DFU without application init.
4. Connect `0x02` / Accept `0x05`.
5. Head `0x40`, sixteen zero body bytes; expect its 20-byte response.
6. Setup `0x42`, 64-byte descriptor. Erase happens before Accept.
7. Send original ciphertext in 4080-byte blocks plus a remainder; await Sync
   `0x01` after every block. Bulk transfers end with a ZLP when required.
8. Await Finished `0x07` after the final checksum verification.
9. JumpAprom `0x08`, reopen APP, and compare the entire installed image.

| Descriptor body offset | Field |
|---|---|
| `0x00` | Application base `0x4000` |
| `0x04` | End-exclusive, base plus plaintext size |
| `0x08` | Plaintext size |
| `0x0c` | Plaintext CRC32 |
| `0x10`, `0x1c`, `0x28` | Model, version, date; each 12 bytes |
| `0x34` | Host random word; unused in the inspected update branch |
| `0x38` | Eight zero bytes |

Device control IDs are an independent counter. Require complete control frames,
check their types and report Error/Reject codes; do not require host-ID echo.
Host receive deadlines are 2 seconds for ordinary ACKs, 20 seconds for erase,
and 5 seconds for final verification. Setup and data blocks are sent once.
The bootloader's receive loop has no data-block address or sequence field.
If an ACK is lost after a write, retransmitting could write the same block at
the next cursor. Recovery starts a fresh update rather than retrying a block.

## Installed-image verification

The loader first checks the uploaded plaintext CRC, then patches image offsets
`0x428..0x42f` with its size and CRC. The following eight bytes are copied from
the descriptor model and already agree in a validated image. Therefore raw
flash differs from the uncommitted upload image. `installed_data()` constructs
the expected final bytes; the CLI compares those bytes after reboot. Comparing
only the version is insufficient: different images can have the same version.

The flash writer's return is not checked in the inspected upload branch, so
Sync alone is not a per-block readback integrity guarantee. Final checksum and
post-reboot readback are both necessary.

## Downgrades and hardware validation

The inspected loader checks a checksum but does not compare version ordering
or verify a digital signature in its update path. The client accepts older and
same-version official packages without changing the transfer protocol. This
establishes protocol support, not hardware validation of every old release.

Verified on 2026-10-28:

- Official signed catalog GET and downloads of 2.0.7 and 1.9.7.
- Package inspection of the local 1.9.9 image and downloaded 2.0.7 image.
- Non-writing package/device checks for both 2.0.7 and older 1.9.7 against
  hardware 2.1 running 1.9.9.
- Bootloader static analysis, including a live read confirming the final
  size/CRC patch on the installed 1.9.9 image.
- Scripted transport tests for delayed/immediate erase responses, independent
  IDs, ciphertext chunking, lost ACK/disconnect, truncated replies and CRC errors.

The complete update cycle was subsequently tested on the connected hardware:

| Transition | Plaintext size / upload CRC | Result |
|---|---|---|
| Original 1.9.9 (2025.9.22) -> 2.0.7 (2026.9.29) | 456896 / `A175E4A0` | Erase, 112 Sync replies, Finished, reboot and full readback passed |
| 2.0.7 -> exact original 1.9.9 (2025.9.22) | 453828 / `7C80B54E` | Erase, 112 Sync replies, Finished, reboot and full readback passed |

Both transitions completed on the first attempt. Erase acknowledgment took
approximately one second. Setup-to-Finished took 3.500 seconds for upgrade and
3.491 seconds for downgrade; backups, reconnects and readback are additional.
The device's erase Accept ID was 3 while the host Setup ID was 4, confirming
the independent reply counter on live hardware.

Before flashing, two independent reads of the installed 1.9.9 application
matched. Normalizing its committed size/CRC words reproduced the exact
plaintext from the previously successful USB capture. The rollback package
reused that capture's original ciphertext and was validated against the current
backup before use, avoiding the inconsistent server object.

An independent final read matched all 453828 original application bytes:
SHA256 `1917eb2f05fb848c4f98323d17cbd6eacc3252dfc0f16bb479f8564e0311417a`.
The acquired bootloader region `[0x4,0x4000)` also matched its pre-test dump:
SHA256 `17d51eeff9fb6abe1a7024a108006248e0aaebdaae52de69a3e26c000565d4bf`.
Final device information, including serial, UUID and authentication state,
matched the pre-test information exactly.

`info` and ADC transactions succeeded after both transitions. This is not a
measurement-accuracy test: the first 2.0.7 ADC sample contained an implausible
CC2 average (61.441 V with instantaneous CC2 0.030 V). Whether that reflects
startup averaging state or a changed ADC layout requires separate analysis.
The meter was restored to its original 1.9.9 image after the test.

USB captures and verbose CLI traces were retained for both transitions.
Interrupted-update recovery, deliberate ACK loss, other hardware revisions
and compatibility of every older release remain untested. The loader
acquisition lacks its first four bytes (initial SP); the unchanged-region
comparison covers only the 16380 acquired bytes.
