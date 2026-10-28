//! egui adapter: egui_plot owns axes/interactions; the shared core draws data.

use std::{cell::RefCell, collections::VecDeque, ops::RangeInclusive, sync::Arc};

use eframe::{egui, egui_wgpu};
use egui_plot::{
    ClosestElem, Cursor, LabelFormatterFn, PlotBounds, PlotGeometry, PlotItem, PlotItemBase, PlotPoint, PlotTransform,
    Points,
};
use km003c_lib::{MeasurementSample, Metric, OfflineRecordingView};
use realtime_plot::{PlotBuffer, PlotConfig, PlotRenderer, PlotView, wgpu};

use crate::metric_color::MetricColor;

/// WebGPU only in browsers: the compute renderer cannot run on WebGL.
pub fn wgpu_options() -> egui_wgpu::WgpuConfiguration {
    let mut setup = egui_wgpu::WgpuSetupCreateNew::without_display_handle();
    #[cfg(target_arch = "wasm32")]
    {
        setup.instance_descriptor.backends = wgpu::Backends::BROWSER_WEBGPU;
    }
    setup.device_descriptor = Arc::new(|adapter| {
        let adapter_limits = adapter.limits();
        let mut limits = realtime_plot::required_wgpu_limits(100_000, 1).using_resolution(adapter_limits.clone());
        // Offline recordings may be larger than the live ring. Allocate on
        // demand, bounded by the adapter's actual storage/buffer limits.
        limits.max_storage_buffer_binding_size = adapter_limits.max_storage_buffer_binding_size;
        limits.max_buffer_size = adapter_limits.max_buffer_size;
        wgpu::DeviceDescriptor {
            required_limits: limits,
            ..Default::default()
        }
    });
    egui_wgpu::WgpuConfiguration {
        wgpu_setup: egui_wgpu::WgpuSetup::CreateNew(setup),
        ..Default::default()
    }
}

#[derive(Clone, Copy)]
pub enum Series<'a> {
    Live {
        samples: &'a VecDeque<MeasurementSample>,
        total: u64,
    },
    Offline(Option<&'a Arc<OfflineRecordingView>>),
}

impl Series<'_> {
    pub fn len(self) -> usize {
        match self {
            Self::Live { samples, .. } => samples.len(),
            Self::Offline(view) => view.map_or(0, |view| view.samples.len()),
        }
    }

    pub fn time_range(self) -> [f64; 2] {
        if self.len() == 0 {
            [0.0, 0.0]
        } else {
            [
                self.point(0, Metric::Voltage).x,
                self.point(self.len() - 1, Metric::Voltage).x,
            ]
        }
    }

    pub fn nearest(self, time: f64) -> Option<usize> {
        let [first, last] = self.time_range();
        if self.len() == 0 || time < first || time > last {
            return None;
        }
        let next = self.lower_bound(time, Metric::Voltage).min(self.len() - 1);
        Some(
            if next > 0 && time - self.point(next - 1, Metric::Voltage).x < self.point(next, Metric::Voltage).x - time {
                next - 1
            } else {
                next
            },
        )
    }

    pub fn extent(self, metric: Metric, time: [f64; 2]) -> Option<[f64; 2]> {
        let start = self.lower_bound(time[0], metric).saturating_sub(1);
        let end = (self.lower_bound(time[1], metric) + 1).min(self.len());
        let mut range = [f64::INFINITY, f64::NEG_INFINITY];
        for i in start..end {
            let y = self.point(i, metric).y;
            if y.is_finite() {
                range[0] = range[0].min(y);
                range[1] = range[1].max(y);
            }
        }
        range[0].is_finite().then_some(range)
    }

    fn first_index(self) -> u64 {
        match self {
            Self::Live { total, .. } => total.saturating_sub(self.len() as u64),
            Self::Offline(_) => 0,
        }
    }

    fn version(self) -> u64 {
        match self {
            Self::Live { total, .. } => total,
            Self::Offline(_) => self.len() as u64,
        }
    }

    pub fn point(self, index: usize, metric: Metric) -> PlotPoint {
        match self {
            Self::Live { samples, .. } => {
                let sample = &samples[index];
                PlotPoint::new(sample.elapsed_seconds(), metric.value(sample))
            }
            Self::Offline(Some(view)) => {
                let sample = view.samples[index];
                PlotPoint::new(
                    sample.elapsed_seconds(),
                    sample.metric_value(metric).unwrap_or(f64::NAN),
                )
            }
            Self::Offline(None) => unreachable!(),
        }
    }

    pub fn lower_bound(self, x: f64, metric: Metric) -> usize {
        let mut lo = 0;
        let mut hi = self.len();
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.point(mid, metric).x < x {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        lo
    }
}

pub struct GpuPlot {
    state: egui_wgpu::RenderState,
    renderer: Option<PlotRenderer>,
    buffer: Option<PlotBuffer>,
    texture_id: Option<egui::TextureId>,
    texture_size: [u32; 2],
    // Keep the Arc to make source identity stable even if an allocator reuses
    // the address of a recording replaced by another download.
    offline: Option<Arc<OfflineRecordingView>>,
    is_live: bool,
    metric: Option<Metric>,
    loaded_start: u64,
    loaded_end: u64,
    bounds_key: Option<(u64, usize, Option<f64>)>,
    bounds: PlotBounds,
    upload_times: Vec<f64>,
    upload_values: Vec<f32>,
}

impl GpuPlot {
    pub fn new(state: egui_wgpu::RenderState) -> Self {
        Self {
            state,
            renderer: None,
            buffer: None,
            texture_id: None,
            texture_size: [0; 2],
            offline: None,
            is_live: true,
            metric: None,
            loaded_start: 0,
            loaded_end: 0,
            bounds_key: None,
            bounds: PlotBounds::NOTHING,
            upload_times: Vec::new(),
            upload_values: Vec::new(),
        }
    }

    pub fn invalidate(&mut self) {
        self.metric = None;
        self.bounds_key = None;
        self.loaded_start = 0;
        self.loaded_end = 0;
        if let Some(buffer) = &self.buffer {
            buffer.clear();
        }
    }

    fn sync_bounds(&mut self, series: Series<'_>, metric: Metric, min_time: Option<f64>) {
        let same_source = match series {
            Series::Live { .. } => self.is_live,
            Series::Offline(view) => {
                !self.is_live
                    && match (&self.offline, view) {
                        (Some(old), Some(new)) => Arc::ptr_eq(old, new),
                        (None, None) => true,
                        _ => false,
                    }
            }
        };
        if !same_source || self.metric != Some(metric) {
            self.invalidate();
            self.renderer = None;
            self.buffer = None;
            self.texture_size = [0; 2];
            self.metric = Some(metric);
            self.is_live = matches!(series, Series::Live { .. });
            self.offline = match series {
                Series::Offline(view) => view.cloned(),
                _ => None,
            };
        }
        let key = (series.version(), series.len(), min_time);
        if self.bounds_key == Some(key) {
            return;
        }
        self.bounds_key = Some(key);
        self.bounds = PlotBounds::NOTHING;
        let start = min_time.map_or(0, |time| series.lower_bound(time, metric));
        for index in start..series.len() {
            let point = series.point(index, metric);
            if point.x.is_finite() && point.y.is_finite() {
                self.bounds.extend_with(&point);
            }
        }
    }

    fn render(
        &mut self,
        series: Series<'_>,
        metric: Metric,
        min_time: Option<f64>,
        transform: &PlotTransform,
        scale: f32,
    ) -> Result<Option<egui::TextureId>, &'static str> {
        if series.len() < 2 {
            return Ok(None);
        }
        let bounds = transform.bounds();
        let x_range = [bounds.min()[0], bounds.max()[0]];
        let y_range = [bounds.min()[1] as f32, bounds.max()[1] as f32];
        if !bounds.is_valid() || !y_range.iter().all(|v| v.is_finite()) || y_range[0] >= y_range[1] {
            return Ok(None);
        }
        // Keep the two boundary neighbours for correctly clipped segments.
        let eligible = min_time.map_or(0, |time| series.lower_bound(time, metric));
        let start = series.lower_bound(x_range[0], metric).saturating_sub(1).max(eligible);
        let end = (series.lower_bound(x_range[1], metric) + 1).min(series.len());
        if end.saturating_sub(start) < 2 {
            return Ok(None);
        }
        let count = end - start;
        let limits = self.state.device.limits();
        let max_capacity = (limits.max_storage_buffer_binding_size.min(limits.max_buffer_size) / 8) as usize;
        if count > max_capacity {
            return Err("Zoom in to display this recording within the GPU's buffer limit");
        }
        let required = count.max(1024).next_power_of_two().min(max_capacity);
        if self.buffer.as_ref().is_none_or(|buffer| buffer.capacity < count) {
            let config = PlotConfig {
                num_channels: 1,
                capacity: required,
                y_min: -1.0,
                y_max: 1.0,
                auto_range: false,
                channel_colors: vec![metric.color().to_normalized_gamma_f32()],
            };
            self.renderer = Some(PlotRenderer::with_format(
                &self.state.device,
                &self.state.queue,
                config,
                wgpu::TextureFormat::Rgba8Unorm,
            ));
            self.buffer = Some(PlotBuffer::new(1, required));
            self.loaded_start = 0;
            self.loaded_end = 0;
            self.texture_size = [0; 2];
        }
        let buffer = self.buffer.as_ref().unwrap();
        let absolute_start = series.first_index() + start as u64;
        let absolute_end = series.first_index() + end as u64;
        let append =
            absolute_start >= self.loaded_start && absolute_end >= self.loaded_end && absolute_start <= self.loaded_end;
        let retained = absolute_start >= self.loaded_start && absolute_end <= self.loaded_end;
        // Existing ring entries may be dropped while streaming. The earliest
        // retained index is tracked below, allowing incremental uploads as the
        // viewport follows the live tail.
        let upload_start = if append || retained {
            self.loaded_end
        } else {
            buffer.clear();
            self.loaded_start = absolute_start;
            absolute_start
        };
        self.upload_times.clear();
        self.upload_values.clear();
        for index in upload_start..absolute_end {
            let point = series.point((index - series.first_index()) as usize, metric);
            self.upload_times.push(point.x);
            self.upload_values.push(point.y as f32);
        }
        buffer.push_timed_batch(&self.upload_times, &self.upload_values);
        if !retained {
            self.loaded_end = absolute_end;
            self.loaded_start = self
                .loaded_start
                .max(absolute_end.saturating_sub(buffer.capacity as u64));
        }

        let frame = transform.frame();
        let output = self.renderer.as_mut().unwrap().render_view(
            buffer,
            PlotView {
                width: (frame.width() * scale).round().max(1.0) as u32,
                height: (frame.height() * scale).round().max(1.0) as u32,
                visible_samples: count as u32,
                view_offset: (self.loaded_end - absolute_end) as u32,
                scale_factor: scale,
                x_range: Some(x_range),
                y_range: Some(y_range),
            },
        );
        let size = [output.texture.width(), output.texture.height()];
        if self.texture_size != size || self.texture_id.is_none() {
            let view = output.texture.create_view(&Default::default());
            let mut renderer = self.state.renderer.write();
            if let Some(id) = self.texture_id {
                renderer.update_egui_texture_from_wgpu_texture(&self.state.device, &view, wgpu::FilterMode::Linear, id);
            } else {
                self.texture_id =
                    Some(renderer.register_native_texture(&self.state.device, &view, wgpu::FilterMode::Linear));
            }
            self.texture_size = size;
        }
        Ok(self.texture_id)
    }
}

impl Drop for GpuPlot {
    fn drop(&mut self) {
        if let Some(id) = self.texture_id {
            self.state.renderer.write().free_texture(&id);
        }
    }
}

pub struct GpuPlotItem<'a> {
    gpu: &'a RefCell<GpuPlot>,
    series: Series<'a>,
    metric: Metric,
    min_time: Option<f64>,
    hover_radius: f32,
    base: PlotItemBase,
}

impl<'a> GpuPlotItem<'a> {
    pub fn new(
        gpu: &'a RefCell<GpuPlot>,
        series: Series<'a>,
        metric: Metric,
        min_time: Option<f64>,
        hover_radius: f32,
    ) -> Self {
        gpu.borrow_mut().sync_bounds(series, metric, min_time);
        Self {
            gpu,
            series,
            metric,
            min_time,
            hover_radius,
            base: PlotItemBase::new(metric.label().to_string()),
        }
    }
}

impl PlotItem for GpuPlotItem<'_> {
    fn shapes(&self, ui: &egui::Ui, transform: &PlotTransform, shapes: &mut Vec<egui::Shape>) {
        match self.gpu.borrow_mut().render(
            self.series,
            self.metric,
            self.min_time,
            transform,
            ui.ctx().pixels_per_point(),
        ) {
            Ok(Some(id)) => {
                // Push into egui_plot's shape list to keep grid, line and cursor
                // ordering correct. No CPU waveform tessellation is performed.
                shapes.push(egui::Shape::image(
                    id,
                    *transform.frame(),
                    egui::Rect::from_min_max(egui::Pos2::ZERO, egui::pos2(1.0, 1.0)),
                    egui::Color32::WHITE,
                ));
            }
            Err(error) => {
                ui.painter().text(
                    transform.frame().center(),
                    egui::Align2::CENTER_CENTER,
                    error,
                    egui::FontId::default(),
                    ui.visuals().error_fg_color,
                );
            }
            Ok(None) => {}
        }
    }

    fn initialize(&mut self, _x_range: RangeInclusive<f64>) {}
    fn color(&self) -> egui::Color32 {
        self.metric.color()
    }
    fn geometry(&self) -> PlotGeometry<'_> {
        PlotGeometry::None
    }
    fn bounds(&self) -> PlotBounds {
        self.gpu.borrow().bounds
    }
    fn base(&self) -> &PlotItemBase {
        &self.base
    }
    fn base_mut(&mut self) -> &mut PlotItemBase {
        &mut self.base
    }

    fn find_closest(&self, point: egui::Pos2, transform: &PlotTransform) -> Option<ClosestElem> {
        let left = transform
            .value_from_position(point - egui::vec2(self.hover_radius, 0.0))
            .x;
        let right = transform
            .value_from_position(point + egui::vec2(self.hover_radius, 0.0))
            .x;
        let first = self
            .min_time
            .map_or(0, |time| self.series.lower_bound(time, self.metric));
        // Search only the screen-space hover band, retaining the original
        // nearest-point behaviour even for dense peaks and steep segments.
        let start = self.series.lower_bound(left, self.metric).max(first);
        let end = (self.series.lower_bound(right, self.metric) + 1).min(self.series.len());
        (start..end)
            .filter_map(|index| {
                let value = self.series.point(index, self.metric);
                value.y.is_finite().then(|| ClosestElem {
                    index,
                    dist_sq: transform.position_from_point(&value).distance_sq(point),
                })
            })
            .min_by(|a, b| a.dist_sq.total_cmp(&b.dist_sq))
    }

    fn on_hover(
        &self,
        response: &egui::Response,
        elem: ClosestElem,
        shapes: &mut Vec<egui::Shape>,
        cursors: &mut Vec<Cursor>,
        plot: &egui_plot::PlotConfig<'_>,
        formatter: Option<&LabelFormatterFn<'_>>,
    ) {
        let point = self.series.point(elem.index, self.metric);
        Points::new(self.name(), vec![[point.x, point.y]]).on_hover(
            response,
            ClosestElem {
                index: 0,
                dist_sq: elem.dist_sq,
            },
            shapes,
            cursors,
            plot,
            formatter,
        );
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use km003c_lib::uom::si::{
        electric_current::ampere,
        electric_potential::volt,
        f64::{ElectricCurrent, ElectricPotential},
    };
    use km003c_lib::{AdcQueueSample, GraphSampleRate, MeasurementAccumulator};

    fn sample(accumulator: &mut MeasurementAccumulator, sequence: u16) -> MeasurementSample {
        let vbus = ElectricPotential::new::<volt>(5.0);
        let ibus = ElectricCurrent::new::<ampere>(-2.0);
        accumulator
            .push(
                AdcQueueSample {
                    sequence,
                    marker: 0,
                    vbus,
                    ibus,
                    power: vbus * ibus,
                    cc1: vbus,
                    cc2: vbus,
                    vdp: vbus,
                    vdm: vbus,
                },
                GraphSampleRate::Sps1000,
            )
            .unwrap()
    }

    #[test]
    fn series_search_uses_device_time_and_signed_metrics() {
        let mut accumulator = MeasurementAccumulator::default();
        let samples = VecDeque::from([
            sample(&mut accumulator, 0),
            sample(&mut accumulator, 1),
            sample(&mut accumulator, 10),
        ]);
        let series = Series::Live {
            samples: &samples,
            total: 103,
        };
        assert_eq!(series.first_index(), 100);
        assert_eq!(series.lower_bound(0.005, Metric::Voltage), 2);
        assert_eq!(series.point(2, Metric::Voltage).x, 0.010);
        assert_eq!(series.point(1, Metric::SignedCurrent).y, -2.0);
        assert_eq!(series.point(1, Metric::Current).y, 2.0);
        assert_eq!(series.nearest(0.002), Some(1));
        assert_eq!(series.nearest(0.009), Some(2));
        assert_eq!(series.nearest(-1.0), None);
        assert_eq!(series.extent(Metric::SignedCurrent, [0.0, 0.01]), Some([-2.0, -2.0]));
    }

    #[test]
    #[ignore = "requires a GPU adapter"]
    fn gpu_cache_wrap_pan_resize_and_metric_changes() {
        let instance = wgpu::Instance::new(wgpu::InstanceDescriptor::new_without_display_handle());
        let adapter = pollster::block_on(instance.request_adapter(&Default::default())).unwrap();
        let (device, queue) = pollster::block_on(adapter.request_device(&wgpu::DeviceDescriptor {
            required_limits: realtime_plot::required_wgpu_limits(100_000, 1).using_resolution(adapter.limits()),
            ..Default::default()
        }))
        .unwrap();
        let target_format = wgpu::TextureFormat::Rgba8Unorm;
        let renderer = egui_wgpu::Renderer::new(&device, target_format, Default::default());
        let mut gpu = GpuPlot::new(egui_wgpu::RenderState {
            instance,
            adapter,
            available_adapters: Vec::new(),
            device,
            queue,
            target_format,
            renderer: Arc::new(egui::epaint::mutex::RwLock::new(renderer)),
            surface_config: egui_wgpu::SurfaceConfig::HIGH_THROUGHPUT,
        });
        let mut accumulator = MeasurementAccumulator::default();
        let mut samples: VecDeque<_> = (0..2048).map(|i| sample(&mut accumulator, i)).collect();
        let transform = |end, width| {
            PlotTransform::new(
                egui::Rect::from_min_size(egui::pos2(50.0, 30.0), egui::vec2(width, 100.0)),
                PlotBounds::from_min_max([end - 0.7, -3.0], [end, 6.0]),
                [false, false],
            )
        };
        let render = |gpu: &mut GpuPlot, samples: &VecDeque<_>, total, metric, end, width| {
            let series = Series::Live { samples, total };
            gpu.sync_bounds(series, metric, None);
            gpu.render(series, metric, None, &transform(end, width), 1.0)
                .unwrap()
                .unwrap()
        };
        let id = render(&mut gpu, &samples, 2048, Metric::Voltage, 2.047, 320.0);
        let buffer_id = gpu.buffer.as_ref().unwrap().write_pos();
        assert_eq!(id, render(&mut gpu, &samples, 2048, Metric::Voltage, 2.047, 320.0));
        assert_eq!(gpu.buffer.as_ref().unwrap().write_pos(), buffer_id);
        assert!(gpu.upload_values.is_empty(), "unchanged frames must not upload samples");

        // Stream through several GPU ring wraps while the CPU ring also evicts.
        for batch in (2048u16..4500).step_by(32) {
            let end = (batch + 32).min(4500);
            for i in batch..end {
                samples.push_back(sample(&mut accumulator, i));
                samples.pop_front();
            }
            render(
                &mut gpu,
                &samples,
                u64::from(end),
                Metric::Voltage,
                f64::from(end - 1) / 1000.0,
                320.0,
            );
            assert!(gpu.upload_values.len() <= 33, "live tail must upload incrementally");
        }
        // Pan back within retained GPU history, then beyond it (reload).
        render(&mut gpu, &samples, 4500, Metric::Voltage, 4.4, 320.0);
        assert!(gpu.upload_values.is_empty());
        render(&mut gpu, &samples, 4500, Metric::Voltage, 3.3, 320.0);
        assert!(!gpu.upload_values.is_empty());
        assert_eq!(id, render(&mut gpu, &samples, 4500, Metric::Voltage, 4.499, 640.0));
        assert_eq!(gpu.texture_size, [640, 100]);
        assert_eq!(
            id,
            render(&mut gpu, &samples, 4500, Metric::SignedCurrent, 4.499, 640.0)
        );
        assert!(gpu.upload_values.iter().all(|value| *value == -2.0));
        let offline = Arc::new(OfflineRecordingView::new(crate::tests::captured_offline_log()));
        let series = Series::Offline(Some(&offline));
        gpu.sync_bounds(series, Metric::SignedCurrent, None);
        let offline_transform = PlotTransform::new(
            *transform(4.499, 640.0).frame(),
            PlotBounds::from_min_max([0.0, -3.0], [20.0, 1.0]),
            [false, false],
        );
        assert_eq!(
            gpu.render(series, Metric::SignedCurrent, None, &offline_transform, 1.0)
                .unwrap(),
            Some(id)
        );
        assert_eq!(gpu.upload_times, vec![0.0, 10.0, 20.0]);
        assert_eq!(gpu.buffer.as_ref().unwrap().available_samples(), 3);
        gpu.invalidate();
        samples.clear();
        accumulator.reset();
        samples.extend([sample(&mut accumulator, 0), sample(&mut accumulator, 1)]);
        render(&mut gpu, &samples, 2, Metric::Voltage, 0.001, 640.0);
        assert_eq!(gpu.buffer.as_ref().unwrap().available_samples(), 2);
    }
}
