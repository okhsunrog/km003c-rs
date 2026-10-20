//! Enumerate previously permitted meters without opening them or prompting.
use futures_util::StreamExt;
use nusb::DeviceInfo;
use std::time::Duration;
use tokio::sync::mpsc;

pub struct BrowserDevices {
    pub devices: Vec<DeviceInfo>,
    pub selected: Option<usize>,
    pub ready: bool,
    updates: mpsc::UnboundedReceiver<Result<Vec<DeviceInfo>, String>>,
    refresh: mpsc::UnboundedSender<()>,
}

impl BrowserDevices {
    pub fn new() -> Self {
        let (tx, updates) = mpsc::unbounded_channel();
        let (refresh, mut refresh_rx) = mpsc::unbounded_channel();
        wasm_bindgen_futures::spawn_local(async move {
            let mut watch = nusb::watch_devices().ok();
            loop {
                let result = km003c_lib::runtime::timeout(Duration::from_secs(3), async {
                    nusb::list_devices().await.map(|devices| {
                        devices
                            .filter(|d| d.vendor_id() == 0x5fc9 && d.product_id() == 0x0063)
                            .collect()
                    })
                })
                .await
                .map_err(|e| e.to_string())
                .and_then(|r| r.map_err(|e| e.to_string()));
                if tx.send(result).is_err() {
                    break;
                }
                if let Some(watch) = watch.as_mut() {
                    tokio::select! {
                        requested = refresh_rx.recv() => if requested.is_none() { break; },
                        event = watch.next() => if event.is_none() { break; },
                    }
                } else if refresh_rx.recv().await.is_none() {
                    break;
                }
            }
        });
        Self {
            devices: Vec::new(),
            selected: None,
            ready: false,
            updates,
            refresh,
        }
    }

    pub fn poll(&mut self, serial: Option<&str>) {
        while let Ok(result) = self.updates.try_recv() {
            self.ready = true;
            if let Ok(devices) = result {
                let selected_serial = self
                    .selected
                    .and_then(|i| self.devices.get(i))
                    .and_then(|d| d.serial_number())
                    .or(serial)
                    .map(str::to_owned);
                self.selected = selected_serial
                    .as_deref()
                    .and_then(|serial| devices.iter().position(|d| d.serial_number() == Some(serial)))
                    .or_else(|| (selected_serial.is_none() && !devices.is_empty()).then_some(0));
                self.devices = devices;
            }
        }
    }

    /// A permission grant need not emit a USB hotplug event.
    pub fn refresh(&mut self) {
        self.selected = None;
        let _ = self.refresh.send(());
    }

    pub fn selected_device(&self) -> Option<DeviceInfo> {
        self.selected.and_then(|i| self.devices.get(i)).cloned()
    }
}
