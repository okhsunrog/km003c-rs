//! Measurement-first layout; all charts share a device-time viewport.
use super::*;
use crate::metric_color::MetricColor;

impl PowerMonitorApp {
    pub(super) fn measurement_cards(&self, ui: &mut egui::Ui) {
        ui.columns(3, |columns| {
            for (column, (label, value, metric)) in columns.iter_mut().zip([
                ("Voltage", self.current_voltage, Metric::Voltage),
                ("Current", self.current_current, Metric::SignedCurrent),
                ("Power", self.current_power, Metric::SignedPower),
            ]) {
                egui::Frame::group(column.style()).show(column, |ui| {
                    ui.set_min_width((ui.available_width() - 4.0).max(0.0));
                    ui.small(label);
                    let size = (ui.available_width() / 7.5).clamp(18.0, 34.0);
                    ui.label(
                        egui::RichText::new(format!("{value:.3} {}", metric.unit()))
                            .monospace()
                            .size(size)
                            .color(readable_color(ui, metric.color())),
                    );
                });
            }
        });
    }

    fn start_acquisition(&mut self) {
        self.acquisition_requested = true;
        if self.device_state.is_some() {
            match self.session.set_streaming(true) {
                Ok(()) => self.stream_command_pending = true,
                Err(error) => self.status = error.to_string(),
            }
        } else {
            #[cfg(not(target_arch = "wasm32"))]
            self.request_connection(true);
            #[cfg(target_arch = "wasm32")]
            self.choose_device(false);
        }
    }

    fn stop_acquisition(&mut self) {
        self.acquisition_requested = false;
        self.stop_recording();
        match self.session.set_streaming(false) {
            Ok(()) => self.stream_command_pending = true,
            Err(error) => self.status = error.to_string(),
        }
    }

    fn disconnect_device(&mut self) {
        self.acquisition_requested = false;
        self.auto_connect_enabled = false;
        self.reconnect_at = None;
        #[cfg(target_arch = "wasm32")]
        {
            self.chooser = None;
        }
        self.stop_recording();
        if let Err(error) = self.session.disconnect() {
            self.status = error.to_string();
        }
    }

    pub(super) fn toggle_view_pause(&mut self) {
        if self.paused_view.is_some() {
            self.paused_view = None;
            self.time_view.live();
        } else {
            let [first, last] = self.series().time_range();
            self.time_view.history = Some(self.time_view.range(first, last, self.time_window.seconds()));
            self.paused_view = Some((self.data_points.clone(), self.total_samples));
        }
    }

    pub(super) fn acquisition_controls(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            let ready = !self.connection_attempt_in_flight && !self.stream_command_pending && !self.offline_busy;
            #[cfg(target_arch = "wasm32")]
            let ready = ready && self.browser_devices.ready;
            if ui
                .add_enabled(ready && !self.streaming, egui::Button::new("Start"))
                .clicked()
            {
                self.start_acquisition();
            }
            if ui
                .add_enabled(ready && self.streaming, egui::Button::new("Stop"))
                .clicked()
            {
                self.stop_acquisition();
            }
            if ui
                .add_enabled(
                    self.device_state.is_some() || self.connection_attempt_in_flight || self.reconnect_at.is_some(),
                    egui::Button::new("Disconnect"),
                )
                .clicked()
            {
                self.disconnect_device();
            }
            ui.separator();
            if ui
                .add_enabled(
                    self.plot_source == PlotSource::Live && !self.data_points.is_empty(),
                    egui::Button::new(if self.paused_view.is_some() {
                        "Resume view"
                    } else {
                        "Pause view"
                    }),
                )
                .on_hover_text("Freeze the displayed samples. Acquisition and recording continue.")
                .clicked()
            {
                self.toggle_view_pause();
            }
            if ui
                .button("Live")
                .on_hover_text("Return to the latest live measurements")
                .clicked()
            {
                self.plot_source = PlotSource::Live;
                self.reset_view();
                self.active_tab = AppTab::Charts;
            }
            ui.separator();
            if let Some(recorder) = &self.recorder {
                if ui
                    .add_enabled(!recorder.is_finishing(), egui::Button::new("Stop recording"))
                    .clicked()
                {
                    self.stop_recording();
                }
            } else if ui
                .add_enabled(
                    self.streaming && !self.offline_busy,
                    egui::Button::new("Record to file"),
                )
                .clicked()
            {
                self.start_recording();
            }
            ui.add_enabled_ui(!self.recording_busy() && !self.offline_busy, |ui| {
                let previous = self.selected_rate;
                egui::ComboBox::from_id_salt("sample_rate")
                    .selected_text(self.selected_rate.label())
                    .show_ui(ui, |ui| {
                        for &rate in SampleRateOption::all() {
                            ui.selectable_value(&mut self.selected_rate, rate, rate.label());
                        }
                    });
                if previous != self.selected_rate && (self.device_state.is_some() || self.connection_attempt_in_flight)
                {
                    let _ = self.session.set_sample_rate(self.selected_rate.to_graph_rate());
                }
            });
        });
    }

    pub(super) fn settings_window(&mut self, ctx: &egui::Context) {
        if !self.settings_open {
            return;
        }
        let mut open = true;
        egui::Window::new("Settings & device").open(&mut open).default_width(380.0).vscroll(true).show(ctx, |ui| {
            self.device_info_section(ui);
            #[cfg(not(target_arch = "wasm32"))]
            ui.checkbox(&mut self.usb_reset, "USB reset on next connection");
            #[cfg(target_arch = "wasm32")]
            ui.add_enabled_ui(self.device_state.is_none() && !self.connection_attempt_in_flight, |ui| {
                let previous = self.browser_devices.selected;
                let label = self.browser_devices.selected_device().map(|d| d.serial_number().unwrap_or("KM003C").to_owned()).unwrap_or("Choose a meter".into());
                egui::ComboBox::from_id_salt("permitted_meter").selected_text(label).show_ui(ui, |ui| {
                    for (index, device) in self.browser_devices.devices.iter().enumerate() {
                        ui.selectable_value(&mut self.browser_devices.selected, Some(index), device.serial_number().unwrap_or("KM003C"));
                    }
                });
                if previous != self.browser_devices.selected {
                    self.selected_serial = self.browser_devices.selected_device().and_then(|d| d.serial_number().map(str::to_owned));
                }
                if ui.button("Choose another USB device…").clicked() { self.choose_device(true); }
            });
            if ui.add_enabled(!self.recording_busy(), egui::Button::new("Clear live data")).clicked() { self.clear_data(); }
            #[cfg(target_arch = "wasm32")]
            ui.small("Browser recording uses memory (128 MiB limit). Stop to download. Keep this tab active to avoid browser throttling.");
        });
        self.settings_open = open;
    }

    fn series(&self) -> Series<'_> {
        match self.plot_source {
            PlotSource::Live => {
                let (samples, total) = self
                    .paused_view
                    .as_ref()
                    .map_or((&self.data_points, self.total_samples), |(samples, total)| {
                        (samples, *total)
                    });
                Series::Live { samples, total }
            }
            PlotSource::Offline => Series::Offline(self.offline_view.as_ref()),
        }
    }

    /// Handle input once before drawing, so every plot uses the same X bounds this frame.
    fn navigate_charts(&mut self, ui: &mut egui::Ui, first: f64, last: f64) -> [f64; 2] {
        let range = self.time_view.range(first, last, self.time_window.seconds());
        let pointer = ui.input(|i| i.pointer.hover_pos());
        let hovered = pointer.and_then(|pos| {
            self.chart_rects
                .iter()
                .flatten()
                .find(|r| r.contains(pos) && ui.rect_contains_pointer(**r))
                .copied()
        });
        let mut drag_started = false;
        if let Some(rect) = hovered {
            let anchor = ((pointer.unwrap().x - rect.left()) / rect.width()).clamp(0.0, 1.0) as f64;
            let (scroll, zoom, shift, pressed, double) = ui.input_mut(|i| {
                let scroll = i.smooth_scroll_delta;
                i.smooth_scroll_delta = egui::Vec2::ZERO;
                (
                    scroll,
                    i.zoom_delta(),
                    i.modifiers.shift,
                    i.pointer.primary_pressed(),
                    i.pointer.button_double_clicked(egui::PointerButton::Primary),
                )
            });
            if double {
                self.time_view.live();
            } else if shift || scroll.x.abs() > scroll.y.abs() {
                let delta = if shift { scroll.x + scroll.y } else { scroll.x };
                self.time_view
                    .pan(range, -delta as f64 / rect.width() as f64, first, last);
            } else if scroll.y != 0.0 || zoom != 1.0 {
                self.time_view.zoom(
                    range,
                    anchor,
                    (scroll.y as f64 * 0.01).exp() * zoom as f64,
                    (last - first).max(self.time_window.seconds().unwrap_or(1.0)).max(60.0) * 2.0,
                );
            }
            if pressed {
                self.dragging_plot = true;
                drag_started = true;
            }
        }
        if self.dragging_plot {
            if ui.input(|i| i.pointer.primary_down()) {
                let width = hovered
                    .or_else(|| self.chart_rects.iter().flatten().next().copied())
                    .map_or(1.0, |r| r.width());
                let delta = ui.input(|i| i.pointer.delta().x);
                if delta != 0.0 && !drag_started {
                    self.time_view.pan(
                        self.time_view.range(first, last, self.time_window.seconds()),
                        -delta as f64 / width as f64,
                        first,
                        last,
                    );
                }
            } else {
                self.dragging_plot = false;
            }
        }
        let range = self.time_view.range(first, last, self.time_window.seconds());
        self.shared_cursor = hovered
            .zip(pointer)
            .map(|(rect, pos)| range[0] + (pos.x - rect.left()) as f64 / rect.width() as f64 * (range[1] - range[0]));
        range
    }

    pub(super) fn plots_panel(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.label(if self.plot_source == PlotSource::Offline {
                "Offline recording"
            } else if self.paused_view.is_some() {
                if self.streaming {
                    "View paused · acquisition continues"
                } else {
                    "View paused · acquisition stopped"
                }
            } else if self.time_view.history.is_some() {
                "History"
            } else {
                "Live measurements"
            });
            let previous = self.time_window;
            egui::ComboBox::from_id_salt("time_window")
                .selected_text(self.time_window.label())
                .show_ui(ui, |ui| {
                    for &window in TimeWindow::all() {
                        ui.selectable_value(&mut self.time_window, window, window.label());
                    }
                });
            if previous != self.time_window {
                self.time_view.live();
            }
            ui.small("Wheel: zoom time · drag: history · double click: follow latest");
        });
        let [first, last] = self.series().time_range();
        let time_range = self.navigate_charts(ui, first, last);
        let plot_height = ((ui.available_height() - 90.0) / 3.0).max(60.0);
        for index in 0..3 {
            ui.horizontal_wrapped(|ui| {
                let previous = self.plot_metrics[index];
                egui::ComboBox::from_id_salt(("plot_metric", index))
                    .selected_text(previous.label())
                    .width(160.0)
                    .show_ui(ui, |ui| {
                        for metric in Metric::ALL {
                            if self.plot_source == PlotSource::Live || metric.supports_offline() {
                                ui.selectable_value(&mut self.plot_metrics[index], metric, metric.label());
                            }
                        }
                    });
                let previous_mode = self.plot_scales[index].mode;
                egui::ComboBox::from_id_salt(("plot_scale", index))
                    .selected_text(match previous_mode {
                        PlotScaleMode::Stepped => "Stepped Y",
                        PlotScaleMode::Fit => "Fit signal",
                        PlotScaleMode::Manual => "Manual Y",
                    })
                    .width(100.0)
                    .show_ui(ui, |ui| {
                        for (mode, label) in [
                            (PlotScaleMode::Stepped, "Stepped Y"),
                            (PlotScaleMode::Fit, "Fit signal"),
                            (PlotScaleMode::Manual, "Manual Y"),
                        ] {
                            ui.selectable_value(&mut self.plot_scales[index].mode, mode, label);
                        }
                    });
                if previous != self.plot_metrics[index] || previous_mode != self.plot_scales[index].mode {
                    self.vertical_scales[index].reset();
                }
                if self.plot_scales[index].mode == PlotScaleMode::Manual {
                    ui.add(
                        egui::DragValue::new(&mut self.plot_scales[index].min)
                            .speed(0.1)
                            .prefix("Min "),
                    );
                    ui.add(
                        egui::DragValue::new(&mut self.plot_scales[index].max)
                            .speed(0.1)
                            .prefix("Max "),
                    );
                    if self.plot_scales[index].min >= self.plot_scales[index].max {
                        ui.label("Min must be below max");
                    }
                }
                ui.small(self.plot_metrics[index].unit());
            });
            let metric = self.plot_metrics[index];
            let extent = self.series().extent(metric, time_range);
            let held = self.time_view.history.is_some()
                || self.paused_view.is_some()
                || self.plot_source == PlotSource::Offline;
            let y =
                self.vertical_scales[index].range(metric, self.plot_scales[index], extent, held, ui.input(|i| i.time));
            let series = self.series();
            let gpu_plots = &self.gpu_plots;
            let nearest = self.shared_cursor.and_then(|time| series.nearest(time));
            let response = Plot::new(("measurement_plot", index))
                .id(egui::Id::new(("measurement_plot", index)))
                .label_formatter(|_| None)
                .height(plot_height)
                .show_x(false)
                .show_y(false)
                .custom_y_axes(vec![
                    egui_plot::AxisHints::new_y()
                        .formatter(|mark, _| chart_view::format_tick(mark.value, mark.step_size)),
                ])
                .y_axis_min_width(52.0)
                .y_grid_spacer(egui_plot::uniform_grid_spacer(|input| {
                    // Decimal 1/2/5 ticks remain readable in short, stacked plots.
                    let target = input.base_step_size.max(f64::MIN_POSITIVE) * 3.0;
                    let decade = 10_f64.powf(target.log10().floor());
                    let step = [1.0, 2.0, 5.0, 10.0]
                        .into_iter()
                        .map(|n| n * decade)
                        .find(|&n| n >= target)
                        .unwrap_or(10.0 * decade);
                    [step / 5.0, step, step * 5.0]
                }))
                .auto_bounds(false)
                .show_grid(true)
                .allow_zoom(false)
                .allow_drag(false)
                .allow_scroll(false)
                .allow_boxed_zoom(false)
                .allow_axis_zoom_drag(false)
                .allow_double_click_reset(false)
                .show(ui, |plot_ui| {
                    plot_ui.set_plot_bounds(PlotBounds::from_min_max([time_range[0], y[0]], [time_range[1], y[1]]));
                    if let Some(gpu_plots) = gpu_plots {
                        plot_ui.add(GpuPlotItem::new(&gpu_plots[index], series, metric, None, 0.0));
                    }
                    if let Some(time) = self.shared_cursor {
                        plot_ui.vline(egui_plot::VLine::new("Time cursor", time).color(egui::Color32::GRAY));
                    }
                    if let Some(sample) = nearest {
                        let point = series.point(sample, metric);
                        plot_ui.points(
                            egui_plot::Points::new("Sample", vec![[point.x, point.y]])
                                .radius(3.5)
                                .color(metric.color()),
                        );
                    }
                });
            let frame = *response.transform.frame();
            if let Some(sample) = nearest {
                response.response.on_hover_ui_at_pointer(|ui| {
                    ui.monospace(chart_view::timestamp(series.point(sample, metric).x));
                    for metric in [Metric::Voltage, Metric::SignedCurrent, Metric::SignedPower] {
                        let point = series.point(sample, metric);
                        ui.monospace(format!("{}: {:.4} {}", metric.label(), point.y, metric.unit()));
                    }
                });
            }
            self.chart_rects[index] = Some(frame);
        }
    }
}
