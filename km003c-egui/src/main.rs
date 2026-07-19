mod pd_decoder;

use eframe::egui;
use egui_plot::{Line, Plot, PlotPoints};
use km003c_lib::{
    AdcQueueSample, DeviceConfig, DeviceState, GraphSampleRate, KM003C,
    packet::{Attribute, AttributeSet},
    pd::{PdEvent, PdStatus},
};
use pd_decoder::{DecodedPdEntry, PdCategory, PdDecoder};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Message from USB task to UI
#[derive(Debug, Clone)]
enum UsbMessage {
    /// Device connected and initialized
    Connected(Arc<DeviceState>),
    /// Connection failed
    ConnectionFailed(String),
    /// New AdcQueue samples received
    Samples(Vec<AdcQueueSample>),
    /// PD events received from device
    PdEvents(Vec<PdEvent>),
    /// PD status (CC line voltages)
    PdStatusUpdate(PdStatus),
    /// Streaming started at given rate
    StreamingStarted(GraphSampleRate),
    /// Streaming stopped
    StreamingStopped,
    /// Error during streaming
    Error(String),
    /// Disconnected
    Disconnected,
}

/// Command from UI to USB task
#[derive(Debug, Clone)]
enum UsbCommand {
    /// Connect to device and start streaming
    Connect(GraphSampleRate, bool),
    /// Change sample rate (stops current streaming, starts with new rate)
    SetSampleRate(GraphSampleRate),
    /// Stop streaming and disconnect
    Disconnect,
}

/// Sample rate options for the UI
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SampleRateOption {
    Sps2,
    Sps10,
    Sps50,
    Sps1000,
}

impl SampleRateOption {
    fn to_graph_rate(self) -> GraphSampleRate {
        match self {
            Self::Sps2 => GraphSampleRate::Sps2,
            Self::Sps10 => GraphSampleRate::Sps10,
            Self::Sps50 => GraphSampleRate::Sps50,
            Self::Sps1000 => GraphSampleRate::Sps1000,
        }
    }

    fn from_graph_rate(rate: GraphSampleRate) -> Self {
        match rate {
            GraphSampleRate::Sps2 => Self::Sps2,
            GraphSampleRate::Sps10 => Self::Sps10,
            GraphSampleRate::Sps50 => Self::Sps50,
            GraphSampleRate::Sps1000 => Self::Sps1000,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Sps2 => "2 SPS",
            Self::Sps10 => "10 SPS",
            Self::Sps50 => "50 SPS",
            Self::Sps1000 => "1000 SPS",
        }
    }

    fn all() -> &'static [Self] {
        &[Self::Sps2, Self::Sps10, Self::Sps50, Self::Sps1000]
    }
}

/// Time window for plot display
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TimeWindow {
    Sec2,
    Sec10,
    Sec30,
    Min1,
    Min5,
    All,
}

impl TimeWindow {
    fn seconds(self) -> Option<f64> {
        match self {
            Self::Sec2 => Some(2.0),
            Self::Sec10 => Some(10.0),
            Self::Sec30 => Some(30.0),
            Self::Min1 => Some(60.0),
            Self::Min5 => Some(300.0),
            Self::All => None,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Sec2 => "2 sec",
            Self::Sec10 => "10 sec",
            Self::Sec30 => "30 sec",
            Self::Min1 => "1 min",
            Self::Min5 => "5 min",
            Self::All => "All",
        }
    }

    fn all() -> &'static [Self] {
        &[Self::Sec2, Self::Sec10, Self::Sec30, Self::Min1, Self::Min5, Self::All]
    }
}

struct PowerMonitorApp {
    /// Data points for plotting (timestamp, voltage, current, power)
    data_points: VecDeque<(f64, f64, f64, f64)>,
    /// Receiver for USB messages
    usb_receiver: mpsc::UnboundedReceiver<UsbMessage>,
    /// Sender for commands to USB task
    cmd_sender: mpsc::UnboundedSender<UsbCommand>,
    /// Device state (available after connection)
    device_state: Option<Arc<DeviceState>>,
    /// Connection status string
    status: String,
    /// Is streaming active
    streaming: bool,
    /// Current sample rate (synced with device)
    current_rate: SampleRateOption,
    /// Selected sample rate in UI (may differ while changing)
    selected_rate: SampleRateOption,
    /// Time window for plot display
    time_window: TimeWindow,
    /// Maximum data points to keep (safety cap)
    max_points: usize,
    /// Total samples received
    total_samples: u64,
    /// Last sequence number (for gap detection)
    last_sequence: Option<u16>,
    /// Dropped sample count
    dropped_samples: u64,
    /// Current readings for display
    current_voltage: f64,
    current_current: f64,
    current_power: f64,
    /// Time offset for plotting (first sample time)
    time_base: Option<std::time::Instant>,
    /// PD protocol decoder
    pd_decoder: PdDecoder,
    /// Decoded PD log entries
    pd_log: VecDeque<DecodedPdEntry>,
    /// Max PD log entries
    max_pd_entries: usize,
    /// Current PD status
    pd_status: Option<PdStatus>,
    /// Auto-scroll PD log
    pd_auto_scroll: bool,
    /// PD panel visible
    pd_panel_visible: bool,
    /// Whether to perform USB reset on connect
    usb_reset: bool,
}

impl PowerMonitorApp {
    fn new(usb_receiver: mpsc::UnboundedReceiver<UsbMessage>, cmd_sender: mpsc::UnboundedSender<UsbCommand>) -> Self {
        Self {
            data_points: VecDeque::new(),
            usb_receiver,
            cmd_sender,
            device_state: None,
            status: "Connecting...".to_string(),
            streaming: false,
            current_rate: SampleRateOption::Sps50,
            selected_rate: SampleRateOption::Sps50,
            time_window: TimeWindow::Sec30,
            max_points: 100000, // Safety cap for memory
            total_samples: 0,
            last_sequence: None,
            dropped_samples: 0,
            current_voltage: 0.0,
            current_current: 0.0,
            current_power: 0.0,
            time_base: None,
            pd_decoder: PdDecoder::new(),
            pd_log: VecDeque::new(),
            max_pd_entries: 1000,
            pd_status: None,
            pd_auto_scroll: true,
            pd_panel_visible: true,
            usb_reset: !cfg!(target_os = "macos"),
        }
    }

    fn process_messages(&mut self) {
        while let Ok(msg) = self.usb_receiver.try_recv() {
            match msg {
                UsbMessage::Connected(state) => {
                    self.status = format!("Connected: {}", state.model());
                    self.device_state = Some(state);
                }
                UsbMessage::ConnectionFailed(err) => {
                    self.status = format!("Connection failed: {}", err);
                }
                UsbMessage::Samples(samples) => {
                    if self.time_base.is_none() {
                        self.time_base = Some(std::time::Instant::now());
                    }
                    let time_base = self.time_base.unwrap();

                    let rate = self.current_rate.to_graph_rate();
                    for sample in &samples {
                        if let Some(last_seq) = self.last_sequence {
                            self.dropped_samples += rate.missing_samples(last_seq, sample.sequence) as u64;
                        }
                        self.last_sequence = Some(sample.sequence);

                        // Calculate timestamp based on sample rate
                        let timestamp = time_base.elapsed().as_secs_f64();

                        self.data_points.push_back((
                            timestamp,
                            sample.vbus_v,
                            sample.ibus_a.abs(),
                            sample.power_w.abs(),
                        ));

                        // Update current readings
                        self.current_voltage = sample.vbus_v;
                        self.current_current = sample.ibus_a;
                        self.current_power = sample.power_w;

                        self.total_samples += 1;

                        // Limit data points
                        while self.data_points.len() > self.max_points {
                            self.data_points.pop_front();
                        }
                    }
                }
                UsbMessage::StreamingStarted(rate) => {
                    self.streaming = true;
                    self.current_rate = SampleRateOption::from_graph_rate(rate);
                    self.selected_rate = self.current_rate;
                    self.status = format!("Streaming at {}", self.current_rate.label());
                    // Reset sequence tracking because the expected step changed.
                    self.last_sequence = None;
                }
                UsbMessage::PdEvents(events) => {
                    for event in &events {
                        let entries = self.pd_decoder.decode_event(event);
                        for entry in entries {
                            self.pd_log.push_back(entry);
                            while self.pd_log.len() > self.max_pd_entries {
                                self.pd_log.pop_front();
                            }
                        }
                    }
                }
                UsbMessage::PdStatusUpdate(status) => {
                    self.pd_status = Some(status);
                }
                UsbMessage::StreamingStopped => {
                    self.streaming = false;
                    self.status = "Stopped".to_string();
                }
                UsbMessage::Error(err) => {
                    self.status = format!("Error: {}", err);
                }
                UsbMessage::Disconnected => {
                    self.status = "Disconnected".to_string();
                    self.streaming = false;
                    self.device_state = None;
                }
            }
        }
    }

    fn clear_data(&mut self) {
        self.data_points.clear();
        self.total_samples = 0;
        self.dropped_samples = 0;
        self.last_sequence = None;
        self.time_base = None;
        info!("Data cleared");
    }

    fn clear_pd_log(&mut self) {
        self.pd_log.clear();
        info!("PD log cleared");
    }
}

impl eframe::App for PowerMonitorApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.process_messages();

        // Request repaints - fast when streaming, slower when idle
        if self.streaming {
            ctx.request_repaint_after(Duration::from_millis(16)); // ~60fps when streaming
        } else {
            ctx.request_repaint_after(Duration::from_millis(100)); // 10fps when idle
        }

        // Top panel with device info
        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("POWER-Z KM003C Monitor");
                ui.separator();

                // Status indicator
                let status_color = if self.streaming {
                    egui::Color32::GREEN
                } else if self.device_state.is_some() {
                    egui::Color32::YELLOW
                } else {
                    egui::Color32::RED
                };
                ui.colored_label(status_color, &self.status);
            });
        });

        // Left panel with device info and controls
        egui::SidePanel::left("info_panel").min_width(220.0).show(ctx, |ui| {
            ui.heading("Device Info");
            ui.separator();

            if let Some(state) = &self.device_state {
                egui::Grid::new("device_info_grid")
                    .num_columns(2)
                    .spacing([10.0, 4.0])
                    .show(ui, |ui| {
                        ui.label("Model:");
                        ui.label(&state.info.model);
                        ui.end_row();

                        ui.label("Firmware:");
                        ui.label(&state.info.fw_version);
                        ui.end_row();

                        ui.label("FW Date:");
                        ui.label(&state.info.fw_date);
                        ui.end_row();

                        ui.label("HW Version:");
                        ui.label(&state.info.hw_version);
                        ui.end_row();

                        ui.label("Mfg Date:");
                        ui.label(&state.info.mfg_date);
                        ui.end_row();

                        ui.label("Serial:");
                        ui.label(&state.info.serial_id);
                        ui.end_row();

                        ui.label("Hardware ID:");
                        ui.label(format!("{}", state.hardware_id));
                        ui.end_row();

                        ui.label("Auth Level:");
                        ui.label(format!("{}", state.auth_level));
                        ui.end_row();

                        ui.label("AdcQueue:");
                        ui.colored_label(
                            if state.adcqueue_enabled {
                                egui::Color32::GREEN
                            } else {
                                egui::Color32::RED
                            },
                            if state.adcqueue_enabled { "Enabled" } else { "Disabled" },
                        );
                        ui.end_row();
                    });
            } else {
                ui.label("Not connected");
            }

            ui.add_space(20.0);
            ui.separator();
            ui.heading("Current Readings");
            ui.separator();

            egui::Grid::new("readings_grid")
                .num_columns(2)
                .spacing([10.0, 4.0])
                .show(ui, |ui| {
                    ui.label("Voltage:");
                    ui.label(format!("{:.3} V", self.current_voltage));
                    ui.end_row();

                    ui.label("Current:");
                    ui.label(format!("{:.3} A", self.current_current.abs()));
                    ui.end_row();

                    ui.label("Power:");
                    ui.label(format!("{:.3} W", self.current_power.abs()));
                    ui.end_row();
                });

            ui.add_space(20.0);
            ui.separator();
            ui.heading("PD Status");
            ui.separator();

            if let Some(pd) = &self.pd_status {
                egui::Grid::new("pd_status_grid")
                    .num_columns(2)
                    .spacing([10.0, 4.0])
                    .show(ui, |ui| {
                        ui.label("CC1:");
                        let cc1_color = if pd.cc1_v > 0.2 {
                            egui::Color32::GREEN
                        } else {
                            egui::Color32::GRAY
                        };
                        ui.colored_label(cc1_color, format!("{:.3} V", pd.cc1_v));
                        ui.end_row();

                        ui.label("CC2:");
                        let cc2_color = if pd.cc2_v > 0.2 {
                            egui::Color32::GREEN
                        } else {
                            egui::Color32::GRAY
                        };
                        ui.colored_label(cc2_color, format!("{:.3} V", pd.cc2_v));
                        ui.end_row();

                        ui.label("Connection:");
                        let connected = pd.cc1_v > 0.2 || pd.cc2_v > 0.2;
                        ui.colored_label(
                            if connected {
                                egui::Color32::GREEN
                            } else {
                                egui::Color32::RED
                            },
                            if connected { "Connected" } else { "No device" },
                        );
                        ui.end_row();
                    });
            } else {
                ui.label("No PD data");
            }

            ui.add_space(20.0);
            ui.separator();
            ui.heading("Statistics");
            ui.separator();

            egui::Grid::new("stats_grid")
                .num_columns(2)
                .spacing([10.0, 4.0])
                .show(ui, |ui| {
                    ui.label("Samples:");
                    ui.label(format!("{}", self.total_samples));
                    ui.end_row();

                    ui.label("Dropped:");
                    ui.colored_label(
                        if self.dropped_samples > 0 {
                            egui::Color32::RED
                        } else {
                            egui::Color32::GREEN
                        },
                        format!("{}", self.dropped_samples),
                    );
                    ui.end_row();

                    ui.label("Buffer:");
                    ui.label(format!("{} pts", self.data_points.len()));
                    ui.end_row();
                });

            ui.add_space(20.0);
            ui.separator();
            ui.heading("Controls");
            ui.separator();

            // Sample rate selector
            ui.horizontal(|ui| {
                ui.label("Sample Rate:");
                let prev_rate = self.selected_rate;
                egui::ComboBox::from_id_salt("sample_rate")
                    .selected_text(self.selected_rate.label())
                    .show_ui(ui, |ui| {
                        for rate in SampleRateOption::all() {
                            ui.selectable_value(&mut self.selected_rate, *rate, rate.label());
                        }
                    });

                // If rate changed, send command to USB task
                if self.selected_rate != prev_rate && self.device_state.is_some() {
                    info!("Sample rate changed to {}", self.selected_rate.label());
                    let _ = self
                        .cmd_sender
                        .send(UsbCommand::SetSampleRate(self.selected_rate.to_graph_rate()));
                }
            });

            ui.add_space(5.0);

            // Time window selector
            ui.horizontal(|ui| {
                ui.label("Time Window:");
                egui::ComboBox::from_id_salt("time_window")
                    .selected_text(self.time_window.label())
                    .show_ui(ui, |ui| {
                        for window in TimeWindow::all() {
                            ui.selectable_value(&mut self.time_window, *window, window.label());
                        }
                    });
            });

            ui.add_space(10.0);

            ui.horizontal(|ui| {
                if ui.button("Clear Data").clicked() {
                    self.clear_data();
                }
            });

            ui.add_space(5.0);

            if self.streaming {
                if ui.button("Disconnect").clicked() {
                    info!("Disconnect requested");
                    let _ = self.cmd_sender.send(UsbCommand::Disconnect);
                }
            } else if self.device_state.is_none() {
                ui.checkbox(&mut self.usb_reset, "USB reset on connect");
                if ui.button("Connect").clicked() {
                    info!("Connect requested");
                    let _ = self
                        .cmd_sender
                        .send(UsbCommand::Connect(self.selected_rate.to_graph_rate(), self.usb_reset));
                }
            }

            ui.add_space(20.0);
            ui.separator();
            ui.heading("PD Log");
            ui.separator();

            ui.horizontal(|ui| {
                ui.checkbox(&mut self.pd_panel_visible, "Show PD Panel");
            });

            ui.horizontal(|ui| {
                ui.checkbox(&mut self.pd_auto_scroll, "Auto-scroll");
                if ui.button("Clear PD Log").clicked() {
                    self.clear_pd_log();
                }
            });

            ui.label(format!("PD entries: {}", self.pd_log.len()));
        });

        // Bottom panel with PD log
        if self.pd_panel_visible {
            egui::TopBottomPanel::bottom("pd_panel")
                .resizable(true)
                .min_height(100.0)
                .default_height(200.0)
                .show(ctx, |ui| {
                    ui.heading("USB PD Protocol Log");
                    ui.separator();

                    let text_style = egui::TextStyle::Monospace;
                    let row_height = ui.text_style_height(&text_style);

                    egui::ScrollArea::vertical()
                        .auto_shrink([false; 2])
                        .stick_to_bottom(self.pd_auto_scroll)
                        .show(ui, |ui| {
                            for entry in &self.pd_log {
                                let color = match entry.category {
                                    PdCategory::Connect => egui::Color32::GREEN,
                                    PdCategory::Disconnect => egui::Color32::RED,
                                    PdCategory::SourceCaps => egui::Color32::from_rgb(100, 149, 237), // Cornflower blue
                                    PdCategory::Request => egui::Color32::YELLOW,
                                    PdCategory::Control => egui::Color32::GRAY,
                                    PdCategory::Extended => egui::Color32::from_rgb(255, 165, 0), // Orange
                                    PdCategory::Error => egui::Color32::from_rgb(255, 80, 80),    // Light red
                                };

                                ui.colored_label(
                                    color,
                                    egui::RichText::new(&entry.summary).monospace().size(row_height),
                                );

                                for detail in &entry.details {
                                    ui.colored_label(
                                        color.gamma_multiply(0.8),
                                        egui::RichText::new(format!("  {}", detail))
                                            .monospace()
                                            .size(row_height),
                                    );
                                }
                            }
                        });
                });
        }

        // Main panel with plots
        egui::CentralPanel::default().show(ctx, |ui| {
            let available_height = ui.available_height();
            let plot_height = (available_height - 30.0) / 3.0;

            // Calculate time cutoff for filtering
            // When streaming, use real elapsed time; when stopped, use last data point time
            let current_time = if self.streaming {
                self.time_base.map(|tb| tb.elapsed().as_secs_f64()).unwrap_or(0.0)
            } else {
                // Use the last data point's timestamp when not streaming
                self.data_points.back().map(|(t, _, _, _)| *t).unwrap_or(0.0)
            };
            let min_time = self
                .time_window
                .seconds()
                .map(|window| (current_time - window).max(0.0));

            // Filter function for time window
            let in_window = |t: &f64| -> bool {
                match min_time {
                    Some(min) => *t >= min,
                    None => true, // "All" - show everything
                }
            };

            // Voltage plot
            ui.label("Voltage (V)");
            Plot::new("voltage_plot")
                .height(plot_height)
                .show_axes([true, true])
                .show_grid(true)
                .allow_boxed_zoom(true)
                .allow_drag(true)
                .allow_scroll(true)
                .show(ui, |plot_ui| {
                    if !self.data_points.is_empty() {
                        let points: PlotPoints = self
                            .data_points
                            .iter()
                            .filter(|(t, _, _, _)| in_window(t))
                            .map(|(t, v, _, _)| [*t, *v])
                            .collect();
                        plot_ui.line(Line::new("Voltage", points).color(egui::Color32::GREEN).width(1.5));
                    }
                });

            // Current plot
            ui.label("Current (A)");
            Plot::new("current_plot")
                .height(plot_height)
                .show_axes([true, true])
                .show_grid(true)
                .allow_boxed_zoom(true)
                .allow_drag(true)
                .allow_scroll(true)
                .show(ui, |plot_ui| {
                    if !self.data_points.is_empty() {
                        let points: PlotPoints = self
                            .data_points
                            .iter()
                            .filter(|(t, _, _, _)| in_window(t))
                            .map(|(t, _, i, _)| [*t, *i])
                            .collect();
                        plot_ui.line(Line::new("Current", points).color(egui::Color32::BLUE).width(1.5));
                    }
                });

            // Power plot
            ui.label("Power (W)");
            Plot::new("power_plot")
                .height(plot_height)
                .show_axes([true, true])
                .show_grid(true)
                .allow_boxed_zoom(true)
                .allow_drag(true)
                .allow_scroll(true)
                .show(ui, |plot_ui| {
                    if !self.data_points.is_empty() {
                        let points: PlotPoints = self
                            .data_points
                            .iter()
                            .filter(|(t, _, _, _)| in_window(t))
                            .map(|(t, _, _, p)| [*t, *p])
                            .collect();
                        plot_ui.line(
                            Line::new("Power", points)
                                .color(egui::Color32::from_rgb(255, 165, 0)) // Orange
                                .width(1.5),
                        );
                    }
                });
        });
    }
}

async fn usb_streaming_task(tx: mpsc::UnboundedSender<UsbMessage>, mut cmd_rx: mpsc::UnboundedReceiver<UsbCommand>) {
    info!("USB task started, waiting for Connect command");

    // Main loop - wait for commands
    loop {
        // Wait for a command (blocking)
        let cmd = match cmd_rx.recv().await {
            Some(cmd) => cmd,
            None => {
                warn!("Command channel closed");
                break;
            }
        };

        match cmd {
            UsbCommand::Connect(initial_rate, usb_reset) => {
                info!("Connect command received, rate={:?}, reset={}", initial_rate, usb_reset);
                run_streaming_session(&tx, &mut cmd_rx, initial_rate, usb_reset).await;
            }
            UsbCommand::SetSampleRate(_) | UsbCommand::Disconnect => {
                // Ignore these when not connected
                debug!("Ignoring command while disconnected: {:?}", cmd);
            }
        }
    }
}

async fn run_streaming_session(
    tx: &mpsc::UnboundedSender<UsbMessage>,
    cmd_rx: &mut mpsc::UnboundedReceiver<UsbCommand>,
    initial_rate: GraphSampleRate,
    usb_reset: bool,
) {
    // Connect to device with vendor interface (Full mode for AdcQueue)
    let config = if usb_reset {
        DeviceConfig::vendor()
    } else {
        DeviceConfig::vendor().skip_reset()
    };
    let mut device = match KM003C::new(config).await {
        Ok(dev) => dev,
        Err(e) => {
            error!("Failed to connect: {}", e);
            let _ = tx.send(UsbMessage::ConnectionFailed(e.to_string()));
            return;
        }
    };

    // Send device state to UI (always available in Full mode)
    let state = device.state().expect("device in Full mode");
    info!("Connected to {} (FW {})", state.model(), state.firmware_version());

    if !state.adcqueue_enabled {
        error!("AdcQueue not enabled - authentication may have failed");
        let _ = tx.send(UsbMessage::ConnectionFailed("AdcQueue not enabled".to_string()));
        return;
    }

    let _ = tx.send(UsbMessage::Connected(Arc::new(state.clone())));

    // Initial StopGraph to ensure clean state
    info!("Sending initial StopGraph to ensure clean state");
    let _ = device.stop_graph_mode().await;
    // Drain any pending data
    while let Ok(Ok(_)) = tokio::time::timeout(Duration::from_millis(50), device.receive_raw()).await {}

    // Start streaming
    let mut current_rate = initial_rate;
    if let Err(e) = start_streaming(&mut device, current_rate, tx).await {
        error!("Failed to start streaming: {}", e);
        let _ = tx.send(UsbMessage::Error(format!("Start failed: {}", e)));
        let _ = tx.send(UsbMessage::Disconnected);
        return;
    }

    // Streaming loop - poll for data and handle commands
    let mut error_count = 0;
    const MAX_ERRORS: u32 = 10;

    loop {
        // Check for commands from UI (non-blocking)
        match cmd_rx.try_recv() {
            Ok(UsbCommand::SetSampleRate(new_rate)) => {
                if new_rate != current_rate {
                    info!("Changing sample rate to {:?}", new_rate);

                    // Stop current streaming
                    let _ = device.stop_graph_mode().await;
                    let _ = tx.send(UsbMessage::StreamingStopped);

                    // Drain pending data
                    while let Ok(Ok(_)) = tokio::time::timeout(Duration::from_millis(50), device.receive_raw()).await {}

                    // Start with new rate
                    if let Err(e) = start_streaming(&mut device, new_rate, tx).await {
                        error!("Failed to restart streaming: {}", e);
                        let _ = tx.send(UsbMessage::Error(format!("Restart failed: {}", e)));
                        continue;
                    }
                    current_rate = new_rate;
                }
            }
            Ok(UsbCommand::Disconnect) => {
                info!("Disconnect command received");
                break;
            }
            Ok(UsbCommand::Connect(..)) => {
                // Ignore connect while already connected
                debug!("Ignoring Connect while already streaming");
            }
            Err(mpsc::error::TryRecvError::Empty) => {
                // No command, continue polling
            }
            Err(mpsc::error::TryRecvError::Disconnected) => {
                warn!("Command channel disconnected");
                break;
            }
        }

        // Request AdcQueue + PD data using library API
        let mask = AttributeSet::single(Attribute::AdcQueue).with(Attribute::PdPacket);
        match device.request_data(mask).await {
            Ok(packet) => {
                error_count = 0;

                if let Some(queue_data) = packet.get_adc_queue()
                    && !queue_data.samples.is_empty()
                {
                    debug!("Received {} samples", queue_data.samples.len());
                    if tx.send(UsbMessage::Samples(queue_data.samples.clone())).is_err() {
                        warn!("UI closed, stopping");
                        break;
                    }
                }

                if let Some(stream) = packet.get_pd_events() {
                    let _ = tx.send(UsbMessage::PdEvents(stream.events.clone()));
                }
                if let Some(status) = packet.get_pd_status() {
                    let _ = tx.send(UsbMessage::PdStatusUpdate(*status));
                }
            }
            Err(e) => {
                error_count += 1;
                debug!("Request error: {}", e);
                if error_count >= MAX_ERRORS {
                    let _ = tx.send(UsbMessage::Error("Too many errors".to_string()));
                    break;
                }
            }
        }

        // Small delay between requests - adjust based on sample rate
        let delay_ms = match current_rate {
            GraphSampleRate::Sps2 => 200,  // 5 requests/sec for 2 SPS
            GraphSampleRate::Sps10 => 50,  // 20 requests/sec for 10 SPS
            GraphSampleRate::Sps50 => 20,  // 50 requests/sec for 50 SPS
            GraphSampleRate::Sps1000 => 5, // 200 requests/sec for 1000 SPS
        };
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
    }

    // Stop streaming and disconnect
    info!("Stopping streaming");
    let _ = device.stop_graph_mode().await;
    let _ = tx.send(UsbMessage::Disconnected);
}

async fn start_streaming(
    device: &mut KM003C,
    rate: GraphSampleRate,
    tx: &mpsc::UnboundedSender<UsbMessage>,
) -> Result<(), km003c_lib::error::KMError> {
    info!("Starting AdcQueue streaming at {:?}", rate);
    device.start_graph_mode(rate).await?;
    let _ = tx.send(UsbMessage::StreamingStarted(rate));
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    info!("Starting POWER-Z KM003C GUI application");

    // Create channels for communication
    let (usb_tx, usb_rx) = mpsc::unbounded_channel();
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();

    // Spawn USB streaming task
    tokio::spawn(usb_streaming_task(usb_tx, cmd_rx));

    // Auto-connect on startup
    let _ = cmd_tx.send(UsbCommand::Connect(GraphSampleRate::Sps50, !cfg!(target_os = "macos")));

    // Run egui application
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1024.0, 768.0])
            .with_title("POWER-Z KM003C Monitor"),
        ..Default::default()
    };

    let app = PowerMonitorApp::new(usb_rx, cmd_tx);

    eframe::run_native("POWER-Z KM003C Monitor", options, Box::new(|_cc| Ok(Box::new(app))))
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
}
