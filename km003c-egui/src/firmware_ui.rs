//! Firmware selection and confirmation UI; the library owns device maintenance.
use super::*;
use crate::firmware_io;
use km003c_lib::{
    DeviceSelector,
    error::KMError,
    firmware::{
        FirmwareDeviceCheck, FirmwareImage, FirmwareInstallProgress, FirmwareInstallResult, FirmwareInstallStage,
        PreparedFirmwareUpdate,
        catalog::{FirmwareCatalog, FirmwareDownload, FirmwareRelease},
        check_firmware_device,
    },
};

enum Event {
    #[cfg(target_arch = "wasm32")]
    Authorized(Result<Option<String>, String>),
    Catalog(Result<FirmwareCatalog, String>),
    Downloaded(Result<FirmwareDownload, String>),
    Image(Result<Option<FirmwareImage>, String>),
    Checked(Result<FirmwareDeviceCheck, String>),
    Progress(FirmwareInstallProgress),
    Installed(Result<Option<FirmwareInstallResult>, String>),
}

pub(super) struct FirmwareUi {
    tx: mpsc::UnboundedSender<Event>,
    events: mpsc::UnboundedReceiver<Event>,
    releases: Vec<FirmwareRelease>,
    selected: Option<usize>,
    image: Option<Arc<FirmwareImage>>,
    image_source: String,
    checked: Option<FirmwareDeviceCheck>,
    serial: String,
    pub busy: bool,
    pub usb_busy: bool,
    pub installing: bool,
    confirm: bool,
    progress: Option<FirmwareInstallProgress>,
    status: String,
}

impl Default for FirmwareUi {
    fn default() -> Self {
        let (tx, events) = mpsc::unbounded_channel();
        Self {
            tx,
            events,
            releases: Vec::new(),
            selected: None,
            image: None,
            image_source: String::new(),
            checked: None,
            serial: String::new(),
            busy: false,
            usb_busy: false,
            installing: false,
            confirm: false,
            progress: None,
            status: "Choose a catalog build or open a .mencrypt file.".into(),
        }
    }
}

impl FirmwareUi {
    pub fn poll(&mut self) {
        while let Ok(event) = self.events.try_recv() {
            if let Event::Progress(progress) = event {
                self.progress = Some(progress);
                continue;
            }
            self.busy = false;
            self.usb_busy = false;
            self.installing = false;
            match event {
                #[cfg(target_arch = "wasm32")]
                Event::Authorized(result) => match result {
                    Ok(Some(serial)) => {
                        self.serial = serial;
                        self.checked = None;
                        self.status = "Meter authorized. Check it before installing.".into();
                    }
                    Ok(None) => self.status = "No meter selected.".into(),
                    Err(error) => self.status = error,
                },
                Event::Catalog(Ok(catalog)) => {
                    self.releases = catalog.releases().to_vec();
                    self.selected = (!self.releases.is_empty()).then_some(0);
                    self.status = format!("{} firmware builds · {}", self.releases.len(), catalog.source().label());
                    if let Some(reason) = catalog.fallback_reason() {
                        self.status
                            .push_str(&format!(" · official catalog unavailable: {reason}"));
                    }
                }
                Event::Image(Ok(Some(image))) => {
                    self.image = Some(Arc::new(image));
                    self.image_source = "local package".into();
                    self.checked = None;
                    self.status = "Package validated. Check the meter before installing.".into();
                }
                Event::Downloaded(Ok(download)) => {
                    self.image_source = download.source().label().into();
                    self.status = "Package validated. Check the meter before installing.".into();
                    if let Some(reason) = download.fallback_reason() {
                        self.image_source.push_str(" (fallback)");
                        self.status
                            .push_str(&format!(" Official download unavailable: {reason}"));
                    }
                    self.image = Some(Arc::new(download.into_parts().1));
                    self.checked = None;
                }
                Event::Image(Ok(None)) => self.status = "File selection canceled.".into(),
                Event::Checked(Ok(check)) => {
                    self.status = "Meter and package checked. Ready to review installation.".into();
                    self.checked = Some(check);
                }
                Event::Installed(Ok(Some(result))) => {
                    self.status = format!(
                        "Installed {} ({}) and verified {} bytes. Press Start to reconnect.",
                        result.firmware.version, result.firmware.date, result.bytes_verified
                    );
                    self.checked = None;
                }
                Event::Installed(Ok(None)) => self.status = "Installation canceled before flashing.".into(),
                Event::Catalog(Err(error))
                | Event::Downloaded(Err(error))
                | Event::Image(Err(error))
                | Event::Checked(Err(error))
                | Event::Installed(Err(error)) => {
                    self.status = format!("Failed: {error}");
                    self.progress = None;
                    self.checked = None;
                }
                Event::Progress(_) => unreachable!(),
            }
        }
    }

    fn start(&mut self, usb: bool) -> mpsc::UnboundedSender<Event> {
        self.busy = true;
        self.usb_busy = usb;
        self.progress = None;
        self.tx.clone()
    }

    fn selector(&self) -> DeviceSelector {
        if self.serial.trim().is_empty() {
            DeviceSelector::First
        } else {
            DeviceSelector::SerialNumber(self.serial.trim().into())
        }
    }

    fn load_image(&mut self) -> mpsc::UnboundedSender<Event> {
        self.image = None;
        self.image_source.clear();
        self.checked = None;
        self.start(false)
    }
}

impl PowerMonitorApp {
    fn reserve_firmware_usb(&mut self) -> Session {
        self.auto_connect_enabled = false;
        self.acquisition_requested = false;
        self.reconnect_at = None;
        #[cfg(target_arch = "wasm32")]
        {
            self.chooser = None;
        }
        self.session.clone()
    }

    fn check_firmware(&mut self) {
        let Some(image) = self.firmware.image.clone() else {
            return;
        };
        let selector = self.firmware.selector();
        let session = self.reserve_firmware_usb();
        self.firmware.checked = None;
        self.firmware.status = "Releasing measurement session and checking meter...".into();
        let tx = self.firmware.start(true);
        km003c_lib::runtime::spawn(async move {
            let result = async {
                session.disconnect_and_wait().await.map_err(|e| e.to_string())?;
                check_firmware_device(&image, selector).await.map_err(|e| e.to_string())
            }
            .await;
            let _ = tx.send(Event::Checked(result));
        });
    }

    fn install_firmware(&mut self) {
        let (Some(image), Some(check)) = (self.firmware.image.clone(), self.firmware.checked.clone()) else {
            return;
        };
        let session = self.reserve_firmware_usb();
        self.firmware.confirm = false;
        self.firmware.installing = true;
        self.firmware.status = if check.installed.is_some() {
            "Choose where to save the verified application backup."
        } else {
            "Installing from DFU recovery mode..."
        }
        .into();
        let tx = self.firmware.start(true);
        km003c_lib::runtime::spawn(async move {
            let _unload_guard = km003c_lib::runtime::UnloadGuard::new();
            let result = install(image, check, session, tx.clone()).await;
            let _ = tx.send(Event::Installed(result));
        });
    }

    pub(super) fn firmware_panel(&mut self, ui: &mut egui::Ui) {
        self.firmware.poll();
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.heading("Firmware");
            ui.label("Install a newer build, downgrade to an older one, or reinstall from a local package.");
            if self.firmware.serial.is_empty()
                && let Some(state) = &self.device_state
            {
                self.firmware.serial = state.info.serial_id.clone();
            }
            ui.add_enabled_ui(!self.firmware.busy, |ui| {
                ui.horizontal_wrapped(|ui| {
                    #[cfg(target_arch = "wasm32")]
                    if ui.button("Authorize meter...").clicked() {
                        let tx = self.firmware.start(false);
                        km003c_lib::runtime::spawn(async move {
                            let filters = [nusb::DeviceSelector::all().with_vid_pid(0x5fc9, 0x0063)];
                            let result = nusb::request_device(&filters)
                                .await
                                .map(|device| device.map(|d| d.serial_number().unwrap_or_default().to_owned()))
                                .map_err(|e| e.to_string());
                            let _ = tx.send(Event::Authorized(result));
                        });
                    }
                    if ui.button("Refresh catalog").clicked() {
                        let tx = self.firmware.start(false);
                        self.firmware.status = "Loading firmware catalog...".into();
                        km003c_lib::runtime::spawn(async move {
                            let result = firmware_io::catalog().await;
                            let _ = tx.send(Event::Catalog(result));
                        });
                    }
                    if ui.button("Open .mencrypt...").clicked() {
                        let tx = self.firmware.load_image();
                        km003c_lib::runtime::spawn(async move {
                            let _ = tx.send(Event::Image(firmware_io::pick_package().await));
                        });
                    }
                });
                if !self.firmware.releases.is_empty() {
                    let previous = self.firmware.selected;
                    let label = self
                        .firmware
                        .selected
                        .and_then(|i| self.firmware.releases.get(i))
                        .map(build_label)
                        .unwrap_or_else(|| "Select a build".into());
                    egui::ComboBox::from_id_salt("firmware_build")
                        .selected_text(label)
                        .show_ui(ui, |ui| {
                            for (index, release) in self.firmware.releases.iter().enumerate() {
                                ui.selectable_value(&mut self.firmware.selected, Some(index), build_label(release));
                            }
                        });
                    if previous != self.firmware.selected {
                        self.firmware.image = None;
                        self.firmware.checked = None;
                    }
                    if ui.button("Download selected build").clicked()
                        && let Some(release) = self
                            .firmware
                            .selected
                            .and_then(|i| self.firmware.releases.get(i))
                            .cloned()
                    {
                        let tx = self.firmware.load_image();
                        self.firmware.status = "Downloading and validating package...".into();
                        km003c_lib::runtime::spawn(async move {
                            let _ = tx.send(Event::Downloaded(firmware_io::download(release).await));
                        });
                    }
                }
            });
            ui.separator();
            if let Some(image) = self.firmware.image.clone() {
                ui.small(format!("Package source: {}", self.firmware.image_source));
                let metadata = image.metadata();
                ui.strong(format!(
                    "Target: {} {} · {}",
                    metadata.model, metadata.version, metadata.date
                ));
                ui.label(format!("{} bytes · CRC32 {:08X}", metadata.size, metadata.crc32));
                let notes = if metadata.notes_en.trim().is_empty() {
                    &metadata.notes_zh
                } else {
                    &metadata.notes_en
                };
                if !notes.trim().is_empty() {
                    ui.label(notes);
                }
                ui.separator();
                ui.add_enabled_ui(!self.firmware.busy, |ui| {
                    ui.label("Meter USB serial (optional when only one meter is attached)");
                    if ui.text_edit_singleline(&mut self.firmware.serial).changed() {
                        self.firmware.checked = None;
                    }
                });
                let ready = !self.firmware.busy
                    && !self.recording_busy()
                    && !self.offline_busy
                    && self.offline_export.is_none();
                if ui.add_enabled(ready, egui::Button::new("Check meter")).clicked() {
                    self.check_firmware();
                }
                if self.recording_busy() {
                    ui.label("Finish the current recording before checking or installing firmware.");
                }
                if let Some(check) = &self.firmware.checked {
                    preview(ui, check, &image);
                    if ui
                        .add_enabled(ready, egui::Button::new("Review installation..."))
                        .clicked()
                    {
                        self.firmware.confirm = true;
                    }
                }
            }
            if let Some(progress) = self.firmware.progress {
                ui.label(stage_label(progress.stage));
                let fraction = if progress.total_bytes == 0 {
                    0.0
                } else {
                    progress.bytes_done as f32 / progress.total_bytes as f32
                };
                ui.add(
                    egui::ProgressBar::new(fraction.clamp(0.0, 1.0))
                        .text(format!("{} / {} bytes", progress.bytes_done, progress.total_bytes)),
                );
            } else if self.firmware.busy {
                ui.spinner();
            }
            ui.label(&self.firmware.status);
        });
        if self.firmware.confirm && !self.firmware.busy {
            egui::Modal::new(egui::Id::new("confirm_firmware_install")).show(ui.ctx(), |ui| {
                ui.heading("Install firmware?");
                if let (Some(check), Some(image)) = (&self.firmware.checked, &self.firmware.image) {
                    preview(ui, check, image);
                }
                ui.label(
                    "Measurement acquisition will disconnect. Keep the meter connected until verification finishes.",
                );
                if self
                    .firmware
                    .checked
                    .as_ref()
                    .is_some_and(|check| check.installed.is_some())
                {
                    ui.label("The verified application backup must be saved before flash is erased.");
                } else {
                    ui.label("The meter is already in DFU. No application backup is available.");
                }
                ui.horizontal(|ui| {
                    if ui.button("Cancel").clicked() {
                        self.firmware.confirm = false;
                    }
                    if ui.button("Install firmware").clicked() {
                        self.install_firmware();
                    }
                });
            });
        }
    }
}

fn build_label(release: &FirmwareRelease) -> String {
    format!("{} · {} · {}", release.version, release.date, release.id)
}

fn preview(ui: &mut egui::Ui, check: &FirmwareDeviceCheck, image: &FirmwareImage) {
    ui.label(format!(
        "Meter: {} · hardware {}",
        check.usb.serial_number.as_deref().unwrap_or("unavailable"),
        check.info.hw_version
    ));
    let current = check
        .installed
        .as_ref()
        .map(|f| format!("{} ({})", f.version, f.date))
        .unwrap_or_else(|| "DFU recovery".into());
    ui.label(format!(
        "{current} → {} ({})",
        image.metadata().version,
        image.metadata().date
    ));
    if let Some(installed) = &check.installed {
        ui.small(format!(
            "Current: {} bytes · CRC32 {:08X}",
            installed.size, installed.crc32
        ));
    }
    ui.small(format!(
        "Target: {} bytes · CRC32 {:08X}",
        image.metadata().size,
        image.metadata().crc32
    ));
}

fn stage_label(stage: FirmwareInstallStage) -> &'static str {
    match stage {
        FirmwareInstallStage::CheckingDevice => "Checking meter",
        FirmwareInstallStage::BackingUp => "Reading and validating application backup",
        FirmwareInstallStage::SavingBackup => "Saving application backup",
        FirmwareInstallStage::SwitchingToDfu => "Switching to bootloader",
        FirmwareInstallStage::Transfer(stage) => match stage {
            km003c_lib::firmware::FirmwareUpdateStage::Connecting => "Opening bootloader",
            km003c_lib::firmware::FirmwareUpdateStage::CheckingStatus => "Checking bootloader status",
            km003c_lib::firmware::FirmwareUpdateStage::Erasing => "Erasing application flash",
            km003c_lib::firmware::FirmwareUpdateStage::Writing => "Writing firmware",
            km003c_lib::firmware::FirmwareUpdateStage::Verifying => "Bootloader verification",
            km003c_lib::firmware::FirmwareUpdateStage::Complete => "Transfer complete",
        },
        FirmwareInstallStage::StartingApplication => "Starting application",
        FirmwareInstallStage::ReadingBack => "Verifying installed application",
        FirmwareInstallStage::Complete => "Installation complete",
    }
}

async fn install(
    image: Arc<FirmwareImage>,
    check: FirmwareDeviceCheck,
    session: Session,
    tx: mpsc::UnboundedSender<Event>,
) -> Result<Option<FirmwareInstallResult>, String> {
    let destination = if let Some(installed) = &check.installed {
        let filename = format!(
            "KM003C-{}-{}-{}-{:08X}.bin",
            check.usb.serial_number.as_deref().unwrap_or("backup"),
            installed.version,
            installed.date,
            installed.crc32
        );
        let Some(destination) = firmware_io::pick_backup(&filename).await? else {
            return Ok(None);
        };
        Some(destination)
    } else {
        None
    };
    session.disconnect_and_wait().await.map_err(|e| e.to_string())?;
    let progress = |value| {
        let _ = tx.send(Event::Progress(value));
    };
    let prepared = PreparedFirmwareUpdate::prepare((*image).clone(), check.selector.clone(), progress)
        .await
        .map_err(|e| e.to_string())?;
    let actual = prepared.device();
    if actual.installed != check.installed
        || actual.usb.serial_number != check.usb.serial_number
        || actual.info.hw_version != check.info.hw_version
    {
        return Err("Meter changed since the check. Check it again before installing.".into());
    }
    prepared
        .install(
            move |backup| async move {
                let destination = destination.ok_or_else(|| {
                    KMError::Protocol("Application mode now requires a backup. Check the meter again.".into())
                })?;
                destination.save(backup.data()).await.map_err(KMError::Protocol)
            },
            progress,
        )
        .await
        .map(Some)
        .map_err(|e| e.to_string())
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use km003c_lib::{
        auth::DeviceInfo,
        firmware::{FirmwareUsbDevice, FirmwareUsbMode, InstalledFirmwareInfo},
    };

    fn image() -> FirmwareImage {
        firmware_io::parse_package(include_bytes!("../tests/fixtures/synthetic.mencrypt")).unwrap()
    }

    fn check() -> FirmwareDeviceCheck {
        FirmwareDeviceCheck {
            usb: FirmwareUsbDevice {
                serial_number: Some("test-meter".into()),
                product_string: None,
                mode_string: "APP".into(),
                mode: FirmwareUsbMode::Application,
                port_selector: None,
            },
            selector: DeviceSelector::SerialNumber("test-meter".into()),
            info: DeviceInfo {
                hw_version: "2.1".into(),
                ..Default::default()
            },
            installed: Some(InstalledFirmwareInfo {
                version: "2.0.7".into(),
                date: "2026.9.29".into(),
                size: 456896,
                crc32: 0,
            }),
        }
    }

    #[tokio::test]
    async fn failed_usb_release_aborts_check_before_any_device_access() {
        let (mut app, _events) = crate::tests::test_app();
        let (session, mut commands) = Session::detached();
        app.session = session;
        app.firmware.image = Some(Arc::new(image()));
        app.check_firmware();
        assert!(app.firmware.usb_busy);
        assert!(!app.auto_connect_enabled);
        assert!(matches!(
            commands.recv().await,
            Some(km003c_lib::SessionCommand::Disconnect)
        ));
        let Some(km003c_lib::SessionCommand::AwaitIdle(reply)) = commands.recv().await else {
            panic!("missing barrier")
        };
        assert!(app.firmware.checked.is_none());
        drop(reply);
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        app.firmware.poll();
        assert!(!app.firmware.busy);
        assert!(!app.firmware.usb_busy);
        assert!(app.firmware.checked.is_none());
        assert!(app.firmware.status.contains("session task has stopped"));
    }

    #[test]
    fn progress_keeps_installation_locked_and_failure_invalidates_check() {
        let mut model = FirmwareUi {
            checked: Some(check()),
            ..Default::default()
        };
        model.start(true);
        model.installing = true;
        model
            .tx
            .send(Event::Progress(FirmwareInstallProgress {
                stage: FirmwareInstallStage::BackingUp,
                bytes_done: 100,
                total_bytes: 200,
            }))
            .unwrap();
        model.poll();
        assert!(model.usb_busy && model.installing && model.busy);
        model
            .tx
            .send(Event::Installed(Err("backup storage failed".into())))
            .unwrap();
        model.poll();
        assert!(!model.usb_busy && !model.installing && !model.busy);
        assert!(model.checked.is_none());
        assert_eq!(model.status, "Failed: backup storage failed");
    }

    #[test]
    fn replacing_a_package_invalidates_the_previous_device_check() {
        let mut model = FirmwareUi {
            checked: Some(check()),
            ..Default::default()
        };
        model.tx.send(Event::Image(Ok(Some(image())))).unwrap();
        model.poll();
        assert!(model.image.is_some());
        assert!(model.checked.is_none());
    }

    #[test]
    fn failed_replacement_cannot_reuse_the_previous_target() {
        let mut model = FirmwareUi {
            image: Some(Arc::new(image())),
            checked: Some(check()),
            ..Default::default()
        };
        let tx = model.load_image();
        tx.send(Event::Image(Err("bad package".into()))).unwrap();
        model.poll();
        assert!(model.image.is_none());
        assert!(model.checked.is_none());
    }

    fn shape_text(shape: &egui::epaint::Shape, text: &mut String) {
        match shape {
            egui::epaint::Shape::Text(t) => {
                text.push_str(&t.galley.job.text);
                text.push('\n');
            }
            egui::epaint::Shape::Vec(shapes) => {
                for s in shapes {
                    shape_text(s, text);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn downgrade_confirmation_displays_current_target_and_meter_without_usb() {
        let (mut app, _events) = crate::tests::test_app();
        app.firmware.image = Some(Arc::new(image()));
        app.firmware.checked = Some(check());
        app.firmware.confirm = true;
        let ctx = egui::Context::default();
        let mut text = String::new();
        for _ in 0..3 {
            let output = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(1024.0, 768.0))),
                    ..Default::default()
                },
                |ui| app.firmware_panel(ui),
            );
            text.clear();
            for shape in &output.shapes {
                shape_text(&shape.shape, &mut text);
            }
            output.drop_without_applying_deltas();
        }
        assert!(text.contains("2.0.7 (2026.9.29) → 1.9.7 (2025.9.1)"), "{text}");
        assert!(text.contains("test-meter"));
        assert!(text.contains("Install firmware?"));
    }

    #[test]
    fn firmware_installation_blocks_measurement_start_and_window_close() {
        let (mut app, _events) = crate::tests::test_app();
        let (session, mut commands) = Session::detached();
        app.session = session;
        app.active_tab = AppTab::Firmware;
        app.acquisition_requested = false;
        app.auto_connect_enabled = false;
        app.connection_attempt_in_flight = false;
        app.firmware.busy = true;
        app.firmware.usb_busy = true;
        app.firmware.installing = true;
        let ctx = egui::Context::default();
        let mut input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(1024.0, 768.0))),
            ..Default::default()
        };
        let mut start = None;
        for _ in 0..3 {
            let output = ctx.run_ui(input.clone(), |ui| app.render_ui(ui));
            for shape in &output.shapes {
                if let egui::epaint::Shape::Text(text) = &shape.shape
                    && text.galley.job.text == "Start"
                {
                    start = Some(text.pos + text.galley.size() * 0.5);
                }
            }
            output.drop_without_applying_deltas();
        }
        let position = start.expect("Start button must remain visible");
        input.events = vec![
            egui::Event::PointerMoved(position),
            egui::Event::PointerButton {
                pos: position,
                button: egui::PointerButton::Primary,
                pressed: true,
                modifiers: Default::default(),
            },
            egui::Event::PointerButton {
                pos: position,
                button: egui::PointerButton::Primary,
                pressed: false,
                modifiers: Default::default(),
            },
        ];
        input
            .viewports
            .get_mut(&egui::ViewportId::ROOT)
            .unwrap()
            .events
            .push(egui::ViewportEvent::Close);
        let output = ctx.run_ui(input, |ui| app.render_ui(ui));
        let canceled_close = output.viewport_output[&egui::ViewportId::ROOT]
            .commands
            .iter()
            .any(|command| matches!(command, egui::ViewportCommand::CancelClose));
        output.drop_without_applying_deltas();
        assert!(canceled_close);
        assert!(!app.acquisition_requested);
        assert!(
            commands.try_recv().is_err(),
            "maintenance must not allow measurement commands"
        );
    }
}
