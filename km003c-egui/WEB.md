# egui in the browser

The browser runs the same egui application and km003c-lib session as desktop:
vendor bulk interface 0, initialization and streaming authentication, 2/10/50/1000
SPS measurements, all three selectable plots, accumulation and loss counters,
USB PD capture/decoding, firmware trace, offline catalog/download/plots, live
recording, and CSV/Parquet export. Linux Chrome has been exercised with a real
KM003C running firmware 1.9.9; see [hardware validation](#hardware-validation).

## Use the hosted monitor

Open **[okhsunrog.github.io/km003c-rs](https://okhsunrog.github.io/km003c-rs/)**
in desktop Chrome or Edge with WebGPU support. Connect the meter's PC port, click **Start**,
click the KM003C row in the browser's device chooser, then click its **Connect**
button. Linux users should first complete the [USB setup](#linux-setup).

The initial theme is dark and the interface scale is 150%. The top toolbar has
theme buttons and a **Scale** menu. Large voltage, signed current and signed power readings stay above the charts.
The **Charts**, **USB PD**, and **Recordings** tabs keep the measurement area clear;
**Settings** contains device details and USB selection. Choose the sample rate in
the control row, the time window above the charts, and the metric beside each plot.

**Start/Stop** controls acquisition while retaining the USB connection.
**Pause view** freezes a snapshot while acquisition and file recording continue;
**Resume view** resumes following new samples. **Live** returns from history or an
offline log to the current live measurements. **Disconnect** releases USB and stops
recording. File recording has its own **Record to file/Stop recording** buttons.

Wheel/pinch zoom changes only time, centered on the cursor; dragging pans history.
All three charts share the same time range. Double click returns to following the
latest samples in the displayed source. Hover anywhere in a chart for a shared time
cursor and the nearest sample's elapsed device timestamp and signed V/A/W values.
Y defaults to stable metric-specific steps (voltage ceilings 6, 10, 13, 16, 21, 26 V,
etc., with headroom). It expands immediately and waits 15 seconds before shrinking;
pausing or browsing history holds the stepped range. **Fit signal** shows detail;
**Manual Y** accepts explicit limits. Metric, window and Y preferences persist. Keep the tab in
the foreground during a capture. Stop a recording and wait for its `.parquet`
or `.csv` download before closing the tab.

GitHub Pages serves only the static application. USB communication, decoding,
plotting and recording export run on the computer connected to the meter.
No server-side USB bridge or separate desktop installation is required.

Routine unknown device-status records (`0x45`) are kept as device diagnostics,
not decoded as empty PD packets. The PD tab can show these diagnostics; repeated
statuses and identical errors are grouped with a count and first/last timestamps.
Diagnostic groups retain the first and latest raw headers, including status flags;
real malformed PD packets remain errors. No observed PD traffic is a normal state
for a USB-A cable and does not imply missing power measurements.

## Build and run

Run these commands from the repository root. Install Rust with rustup. The
repository pins Rust 1.99.1 and the wasm target.
Install the pinned frontend builder once:

    cargo install trunk --version 0.21.14 --locked
    trunk serve --release

Open **http://localhost:8080** in desktop Chrome or Edge. Click **Start** and
select the KM003C (VID 5fc9, PID 0063). Permission is requested only from that
button; startup never opens a permission prompt. Cancellation/denial leaves the
button available. On load, previously permitted meters are enumerated without opening USB or
prompting. **Start** directly opens the selected/last permitted meter; a permission
chooser appears only when no permitted selection is available. Permission belongs
to the browser and may be revoked in its site settings. To select another meter,
use **Settings → Choose another USB device…** while disconnected.
After an unexpected unplug the shared hotplug session waits
for the previously selected serial number and authenticates again. Disconnect
cancels waiting and automatic reconnection. Start reconnects when requested.

Use the release build for hardware measurements, especially at 1000 SPS. Debug
builds can delay USB polling while rendering. Both desktop and browser use the
shared [`realtime-plot`](../realtime-plot) wgpu renderer: anti-aliased line
segments when zoomed in, compute min/max envelopes when zoomed out. The original
samples and timestamps are uploaded without CPU downsampling; recording and
export retain their complete data. egui_plot provides axes and overlays; the app coordinates time navigation and
nearest-sample readouts. GPU textures stay on the device, with incremental uploads while live.

The browser requires WebGPU, including compute/storage buffers. There is no
WebGL fallback. Plot parameters use uniform buffers, without optional immediate
data features. If a visible offline range exceeds the adapter's storage-buffer
limit, the chart asks you to zoom in; the recording remains available for export.

    cargo check -p km003c-egui --target wasm32-unknown-unknown --locked
    trunk build --release

The dist directory is a static site; serve it over HTTPS, or HTTP on localhost.
Do not open index.html as a file. Trunk builds with the committed Cargo.lock and
selects the matching wasm-bindgen CLI. The Cargo target configuration opts into
web-sys's unstable WebUSB bindings, as required by nusb. No server USB bridge is
needed.

The **Firmware** tab uses the library's official-first catalog and download
client, with archive fallback on HTTP, CORS, parsing or validation failures.
The source is shown in the catalog status and loaded package details. Browser
requests use short-lived OSS V1 signed URLs; signing stays in the library.
The tab supports local `.mencrypt` packages,
upgrades, downgrades and reinstalls through the shared library installer. Use
**Authorize meter**, select a package, then **Check meter** and review the current
and target builds. Application-mode installation requires a browser with the
File System Access API so the verified backup can be written and closed before
flash is erased. Keep the page and meter connected until readback completes.
If a DFU-mode meter needs a new permission grant, authorize it again and retry.
This browser installation flow has not yet been hardware-tested.

Desktop remains: cargo run -p km003c-egui. Native Polars, file dialogs and file
writer threads are target-specific and are not linked into the browser.

## Publish to GitHub Pages

The [GitHub Pages workflow](../.github/workflows/pages.yml) builds and publishes
the monitor on every push to `main`, including merged pull requests. It can
also be run manually from **Actions → GitHub Pages → Run workflow**; select
`main` to publish. Manual runs on other branches build an artifact without
deploying it.

For a new repository or fork, enable **Settings → Pages → Build and deployment
→ Source → GitHub Actions** once. The workflow uses the standard `GITHUB_TOKEN`;
no personal token or repository secret is needed. Its build job reads Pages
metadata; only the deploy job has `pages: write` and `id-token: write`.
Deployments use the `github-pages` environment. If that environment restricts
deployment branches or requires review, allow `main` and satisfy its rules.
See [GitHub's custom workflow documentation](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages).

The build uses the pinned Rust toolchain, Trunk 0.21.14, the committed
`Cargo.lock`, and the release profile. It passes the Pages `base_path` to
Trunk's `--public-url`, including a trailing slash. Thus JavaScript and WASM
load from `/km003c-rs/` on the project site, or `/` when Pages uses a dedicated
domain. The `dist/` artifact is uploaded and deployed after a successful build;
deployment runs are serialized without cancelling an active deployment.

To reproduce the project-site build locally:

```sh
trunk build --release --public-url /km003c-rs/
```

Serve the contents of `dist/` at `/km003c-rs/` on a local HTTP server, or upload
them to an HTTPS static host with the same path. The Actions deployment summary
and **Settings → Pages** show the published URL. No `gh-pages` branch is used.

## Platform constraints

- Desktop Chromium with WebGPU enabled is required; Firefox/Safari do not
  implement WebUSB. WebGPU renders egui and the plots. A secure context (HTTPS/localhost) and browser USB policy allowing
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
  Parquet is uncompressed and encoded with Apache Arrow Rust's `parquet` crate,
  with its default features disabled. Desktop keeps Polars. Polars 0.55.2,
  even with default features disabled and only Parquet enabled, pulls in
  `tokio/net` through `polars-core`; `mio` then rejects the browser target.
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

Unplug and reconnect the meter's PC connection, then click Start in the browser.
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
should show no driver before Start, or `usbfs` while the browser owns it.

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

Browser recording lifecycle tests run in headless Chrome in CI. Locally, install
`wasm-bindgen-cli` matching the `wasm-bindgen` version in `Cargo.lock`, put
`chromedriver` or `geckodriver` on `PATH`, and run `just web-test`. These tests
check navigation protection during recording and asynchronous export, including
overlapping operations. They do not open USB devices or download real recordings.

For an optional browser smoke test, install Playwright with `vp add playwright`
in a disposable JavaScript project, expose its `node_modules` via `NODE_PATH`,
and run:

    node km003c-egui/tests/browser-smoke.cjs

Run it against `trunk serve --release`. Set `CHROMIUM` to the Chrome/Chromium
executable if it is not `/usr/bin/chromium`. It compiles the shared render/compute shaders on a browser WebGPU device and
checks egui rendering, user activation, VID/PID filtering, cancellation, opening
timeout and retry. Only browser permission/open calls are mocked. It does not emulate KM003C authentication or measurements.

## Hardware validation

Before the WebGPU migration, on 2026-10-19, the release build was tested in desktop Google Chrome on Linux
with KM003C firmware 1.9.9. Checks included connection/authentication, live
1000 SPS plots with PD protocol capture and firmware trace, live Parquet
recording, and downloading/exporting a device-stored recording. The optional
Linux udev rule was tested by rebinding `powerz`: interface 0 was released
automatically while the CDC and HID interfaces remained unchanged.

A 30-second foreground run after the plotting changes received 30,030 samples
with no observed sequence gaps or duplicates. A longer 336.55-second recording
contained 336,537 rows, 14 reported missing samples, 8 discarded sequence
samples and two non-unit sequence transitions. One repeated older sequence
block was accepted after the accumulator's resynchronization threshold; loss
and discard counters alone do not prove that every saved row is unique.
These observations do not establish lossless capture or reconnect/sleep
behavior on every platform. The checklist below covers the remaining scenarios
as well as repeatable acceptance checks.

## Manual validation with a real KM003C

1. Open the site in Chrome/Edge. Cancel the chooser, then deny permission;
   confirm a useful status and another working Start click. Grant access,
   verify model/serial, successful streaming authentication, live readings and
   all three plots. Check 2, 10, 50 and 1000 SPS, metric selection and time windows.
   Reload: Start must reopen the same permitted serial without a chooser. Test
   selecting another meter in Settings and revoking permission in browser settings.
   Wheel/pinch and drag must affect time only, identically on all three plots;
   check the shared hover cursor away from the line and the timestamp/V/A/W values.
   Verify 5.1/9.1/20.1 V stay visible with stepped Y, Fit and Manual work, and signed
   metrics retain negative values. Pause view while recording, wait for more data,
   then Resume view; the file must include samples collected during the pause.
   Stop must halt acquisition while USB remains connected; Start must resume.
   Fetch a device recording while stopped and confirm acquisition stays stopped.
   On an A-to-C cable, check no false empty-message PD errors appear and diagnostics
   remain inspectable with counts, time spans, and first/latest raw headers.
2. At **1000 SPS**, enable PD protocol capture and firmware trace, repeatedly
   negotiate power with a PD source/load, and run at least 5 minutes. Confirm
   continuously advancing plots, PD decode/timestamps, responsive controls and
   report sample/loss/discard counters. Record/export CSV and Parquet, verify
   row counts, signed current, sequence gaps and metadata in a desktop reader.
3. While streaming and while waiting for a reply, unplug the meter. Confirm the
   UI remains responsive, shows waiting/disconnected state, and stops the
   recording. Reattach the same meter: it should reauthenticate and resume.
   Disconnect while waiting must stop automatic reconnection. Repeat after an
   opening/transfer timeout and after revoking permission (new Start/chooser required).
4. Fetch the offline catalog and download a log. Confirm streaming pauses and
   resumes, offline graphs agree with desktop, unavailable channels remain
   unavailable, and CSV/Parquet downloads preserve the device's accumulated
   charge/energy. Test export and recording while PD is active.
5. Repeat connection/reconnection on each supported OS/driver setup. Check tab
   backgrounding and wake-up recovery explicitly; document observed losses.
