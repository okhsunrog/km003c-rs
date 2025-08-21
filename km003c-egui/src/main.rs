use eframe::egui;
use egui_plot::{Line, Plot, PlotPoints};
use km003c_lib::{adc::AdcDataSimple, KM003C};
use std::collections::VecDeque;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

#[derive(Debug, Clone)]
struct DataPoint {
    timestamp: f64,
    voltage: f64,
    current: f64,
}

struct PowerMonitorApp {
    data_points: VecDeque<DataPoint>,
    data_receiver: mpsc::UnboundedReceiver<AdcDataSimple>,
    start_time: Instant,
    connection_status: String,
    max_points: usize,
}

impl PowerMonitorApp {
    fn new(data_receiver: mpsc::UnboundedReceiver<AdcDataSimple>) -> Self {
        Self {
            data_points: VecDeque::new(),
            data_receiver,
            start_time: Instant::now(),
            connection_status: "Connecting...".to_string(),
            max_points: 1000, // Keep last 1000 points (~100 seconds at 10Hz)
        }
    }

    fn update_data(&mut self) {
        // Process all available data from the channel
        while let Ok(adc_data) = self.data_receiver.try_recv() {
            let timestamp = self.start_time.elapsed().as_secs_f64();

            self.data_points.push_back(DataPoint {
                timestamp,
                voltage: adc_data.vbus_v,
                current: adc_data.ibus_a,
            });

            // Keep only the most recent points
            if self.data_points.len() > self.max_points {
                self.data_points.pop_front();
            }

            self.connection_status = format!("Connected - {:.3}V, {:.3}A", adc_data.vbus_v, adc_data.current_abs_a());
        }
    }
}

impl eframe::App for PowerMonitorApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Update data from background task
        self.update_data();

        // Request repaint for smooth updates
        ctx.request_repaint_after(Duration::from_millis(50));

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("POWER-Z KM003C Real-time Monitor");

            ui.horizontal(|ui| {
                ui.label("Status:");
                ui.colored_label(
                    if self.connection_status.starts_with("Connected") {
                        egui::Color32::GREEN
                    } else {
                        egui::Color32::RED
                    },
                    &self.connection_status,
                );
            });

            ui.separator();

            // Voltage Plot (Top)
            ui.label("Voltage (V)");
            let voltage_plot = Plot::new("voltage_plot")
                .legend(egui_plot::Legend::default())
                .show_axes([true, true])
                .show_grid(true)
                .allow_boxed_zoom(true)
                .allow_drag(true)
                .allow_scroll(true)
                .height(200.0)
                .y_axis_label("Voltage (V)");

            voltage_plot.show(ui, |plot_ui| {
                if !self.data_points.is_empty() {
                    // Voltage line (green)
                    let voltage_points: PlotPoints =
                        self.data_points.iter().map(|p| [p.timestamp, p.voltage]).collect();

                    let voltage_line = Line::new("Voltage (V)", voltage_points)
                        .color(egui::Color32::GREEN)
                        .width(2.0);
                    plot_ui.line(voltage_line);
                }
            });

            ui.add_space(10.0);

            // Current Plot (Bottom)
            ui.label("Current (A)");
            let current_plot = Plot::new("current_plot")
                .legend(egui_plot::Legend::default())
                .show_axes([true, true])
                .show_grid(true)
                .allow_boxed_zoom(true)
                .allow_drag(true)
                .allow_scroll(true)
                .height(200.0)
                .y_axis_label("Current (A)");

            current_plot.show(ui, |plot_ui| {
                if !self.data_points.is_empty() {
                    // Current line (blue) - use absolute value for better visibility
                    let current_points: PlotPoints = self
                        .data_points
                        .iter()
                        .map(|p| [p.timestamp, p.current.abs()])
                        .collect();

                    let current_line = Line::new("Current (A)", current_points)
                        .color(egui::Color32::BLUE)
                        .width(2.0);
                    plot_ui.line(current_line);
                }
            });

            ui.separator();

            ui.horizontal(|ui| {
                ui.label(format!("Data points: {}", self.data_points.len()));
                if ui.button("Clear").clicked() {
                    self.data_points.clear();
                    info!("Data cleared by user");
                }
            });
        });
    }
}

async fn usb_polling_task(tx: mpsc::UnboundedSender<AdcDataSimple>) {
    info!("Starting USB polling task");

    // Try to connect to device
    let mut device = match KM003C::new().await {
        Ok(device) => {
            info!("Successfully connected to KM003C device");
            device
        }
        Err(e) => {
            error!("Failed to connect to KM003C device: {}", e);
            return;
        }
    };

    let mut poll_interval = tokio::time::interval(Duration::from_millis(100)); // 10Hz
    let mut error_count = 0;
    const MAX_ERRORS: u32 = 5;

    loop {
        poll_interval.tick().await;

        match device.request_adc_data().await {
            Ok(adc_data) => {
                if let Err(_) = tx.send(adc_data) {
                    warn!("UI receiver dropped, stopping USB polling");
                    break;
                }
                error_count = 0; // Reset error count on success
            }
            Err(e) => {
                error_count += 1;
                error!(
                    "Failed to read ADC data (error {} of {}): {}",
                    error_count, MAX_ERRORS, e
                );

                if error_count >= MAX_ERRORS {
                    error!("Too many consecutive errors, stopping USB polling");
                    break;
                }

                // Wait a bit longer before retrying on error
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }

    info!("USB polling task terminated");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt::init();
    info!("Starting POWER-Z KM003C GUI application");

    // Create channel for communication between USB task and UI
    let (tx, rx) = mpsc::unbounded_channel();

    // Spawn USB polling task
    tokio::spawn(usb_polling_task(tx));

    // Create and run the egui application
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([800.0, 600.0])
            .with_title("POWER-Z KM003C Monitor"),
        ..Default::default()
    };

    let app = PowerMonitorApp::new(rx);

    info!("Starting egui application");
    eframe::run_native("POWER-Z KM003C Monitor", options, Box::new(|_cc| Ok(Box::new(app))))
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
}