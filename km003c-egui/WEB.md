# egui in the browser

The browser runs the same egui application and km003c-lib session as desktop:
vendor bulk interface 0, initialization and streaming authentication, 2/10/50/1000
SPS measurements, all three selectable plots, accumulation and loss counters,
USB PD capture/decoding, firmware trace, offline catalog/download/plots, live
recording, and CSV/Parquet export. Hardware operation still needs validation on a
real KM003C; a successful build or mock permission test does not establish it.

## Build and run

Install Rust with rustup. The repository pins Rust 1.99.1 and the wasm target.
Install the pinned frontend builder once:

    cargo install trunk --version 0.21.14 --locked
    trunk serve

Open **http://localhost:8080** in desktop Chrome or Edge. Click **Connect** and
select the KM003C (VID 5fc9, PID 0063). Permission is requested only from that
button; startup never opens a permission prompt. Cancellation/denial leaves the
button available. After an unexpected unplug the shared hotplug session waits
for the previously selected serial number and authenticates again. Disconnect
cancels waiting; Connect can select another meter.

    cargo check -p km003c-egui --target wasm32-unknown-unknown --locked
    trunk build --release

The dist directory is a static site; serve it over HTTPS, or HTTP on localhost.
Do not open index.html as a file. Trunk builds with the committed Cargo.lock and
selects the matching wasm-bindgen CLI. The Cargo target configuration opts into
web-sys's unstable WebUSB bindings, as required by nusb. No server USB bridge is
needed.

Desktop remains: cargo run -p km003c-egui. Native Polars, file dialogs and file
writer threads are target-specific and are not linked into the browser.

## Platform constraints

- Desktop Chromium is required; Firefox/Safari do not implement WebUSB. WebGL2
  renders egui. A secure context (HTTPS/localhost) and browser USB policy allowing
  access are required. An iframe also needs USB permission delegation.
- WebUSB cannot detach kernel drivers or use protected HID interfaces. Only the
  vendor bulk interface is used. On Linux use the permissions and optional
  driver-unbinding rules described below. On Windows
  interface 0 must use WinUSB (do not replace drivers for the other interfaces).
  The browser reports an open/claim failure if the OS or another app owns it.
- Browser bus addresses are unavailable; reconnect uses the USB serial number.
  No USB reset is performed by the browser UI.
- nusb **0.2.7** is retained in Cargo.lock (WebUSB was added in 0.2.6). Its built-in
  request-device, configuration, claim, endpoint I/O and hotplug APIs are used.
  nusb maps a cancelled/rejected permission prompt to None; the UI therefore
  reports cancellation and permission denial together. Application deadlines
  wrap USB operations, since WebUSB has no transfer timeout/cancellation API.
  A failed stream drops its interface before retry.
- One browser thread runs local asynchronous tasks; there are no Web Workers,
  wasm threads or SharedArrayBuffer requirements. Tokio channels, select and
  async I/O traits are retained without starting a Tokio runtime. Browser timers
  and a browser monotonic clock replace runtime-specific timing. Sample batches
  are consumed by the UI at its scheduled redraws (60 Hz live, 10 Hz idle);
  individual measurements never request a redraw.
- Live recording buffers samples in memory, bounded to 128 MiB of row data;
  stopping creates a download. Reaching the limit stops and downloads the
  collected recording. Encoding yields between 8192-row blocks. The encoded
  file, Vec capacity, row-group buffers and browser Blob need additional memory.
  Preferences are stored as the shared JSON format in browser localStorage.
  Filesystem journal recovery is desktop-only. Browser recordings do not survive tab closure, a browser crash or a rejected
  download. Stop/save before closing the tab. The browser chooses the actual
  directory; “Saved” means the download was handed to it.
- CSV and Parquet retain the desktop 23-column schema, unsigned/signed types,
  null unavailable offline channels and Parquet source/device metadata. Browser
  Parquet is uncompressed and encoded with the pure Rust parquet writer instead
  of Polars; desktop keeps its existing encoder.
- Keep the tab active. Browser background/sleep throttling can overflow the
  instrument queue, especially at 1000 SPS with PD. Loss counters and existing
  session stall recovery remain active; background logging guarantees are weaker
  than those of a desktop process.

## Linux setup

Install the USB permissions rule. If the `powerz` kernel driver is present,
also install the optional WebUSB rule to automatically release vendor interface
0 whenever that driver binds to a KM003C:

```sh
sudo install -m 0644 71-powerz-km003c.rules 72-powerz-km003c-webusb.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
```

Unplug and reconnect the meter's PC connection, then click Connect in the browser.
The optional rule matches only VID/PID `5fc9:0063`, interface 0 and driver
`powerz`. It leaves CDC serial and HID interfaces alone, and does not unload or
blacklist the module. Native applications can still use the vendor interface.
While this rule is installed, the kernel's `powerz` hwmon readings for the KM003C
are unavailable, even with the browser closed.

To apply it to an already connected meter, first disconnect any native or browser
USB session, then run:

```sh
sudo udevadm trigger --action=bind --subsystem-match=usb --attr-match=bInterfaceNumber=00
sudo udevadm settle
```

The trigger visits interface 0 on USB devices; the rule's VID/PID and driver
checks restrict unbinding to KM003C. Confirm with `lsusb -t`: its interface 0
should show no driver before Connect, or `usbfs` while the browser owns it.

On NixOS, install both files through `services.udev.packages` or
`services.udev.extraRules` and rebuild the configuration; `/etc/udev/rules.d` is
managed by NixOS. If copying the rule into a derivation, `/bin/sh` can be replaced
with `${pkgs.runtimeShell}`.

To restore hwmon, remove only `72-powerz-km003c-webusb.rules` (or its NixOS
configuration), reload the rules and reconnect the meter. Keep the permissions
rule for native application access.

## Checks without hardware

    cargo test -p km003c-lib --features usbpd,polars,browser --locked
    cargo check --workspace --all-targets --locked
    cargo test -p km003c-egui --locked
    cargo fmt --all -- --check

The library tests with the browser feature include CSV/Parquet round trips with multiple row groups,
signed values and null offline channels. Library tests cover recorded protocol
captures, session commands, deadlines and pending-operation cleanup.

For an optional browser smoke test, install Playwright (npm install playwright
in a disposable directory), expose its node_modules via NODE_PATH, and run:

    node km003c-egui/tests/browser-smoke.cjs

Run it against trunk serve. Set CHROMIUM to the Chromium executable if it is not
/usr/bin/chromium. It mocks only browser permission/open calls: checks actual
egui rendering, user activation, VID/PID filtering, cancellation, opening timeout
and retry. It does not emulate KM003C authentication or measurements.

## Manual validation with a real KM003C

1. Open the site in Chrome/Edge. Cancel the chooser, then deny permission;
   confirm a useful status and another working Connect click. Grant access,
   verify model/serial, successful streaming authentication, live readings and
   all three plots. Check 2, 10, 50 and 1000 SPS, metric selection and time windows.
2. At **1000 SPS**, enable PD protocol capture and firmware trace, repeatedly
   negotiate power with a PD source/load, and run at least 5 minutes. Confirm
   continuously advancing plots, PD decode/timestamps, responsive controls and
   report sample/loss/discard counters. Record/export CSV and Parquet, verify
   row counts, signed current, sequence gaps and metadata in a desktop reader.
3. While streaming and while waiting for a reply, unplug the meter. Confirm the
   UI remains responsive, shows waiting/disconnected state, and stops the
   recording. Reattach the same meter: it should reauthenticate and resume.
   Disconnect while waiting must stop automatic reconnection. Repeat after an
   opening/transfer timeout and after revoking permission (new Connect required).
4. Fetch the offline catalog and download a log. Confirm streaming pauses and
   resumes, offline graphs agree with desktop, unavailable channels remain
   unavailable, and CSV/Parquet downloads preserve the device's accumulated
   charge/energy. Test export and recording while PD is active.
5. Repeat connection/reconnection on each supported OS/driver setup. Check tab
   backgrounding and wake-up recovery explicitly; document observed losses.
