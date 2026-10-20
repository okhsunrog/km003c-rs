use crate::{PlotBuffer, PlotConfig, PlotRenderer, PlotView, required_wgpu_limits};

fn device() -> (wgpu::Device, wgpu::Queue) {
    let instance = wgpu::Instance::new(wgpu::InstanceDescriptor::new_without_display_handle());
    let adapter = pollster::block_on(instance.request_adapter(&Default::default())).unwrap();
    pollster::block_on(adapter.request_device(&wgpu::DeviceDescriptor {
        required_limits: required_wgpu_limits(32768, 1).using_resolution(adapter.limits()),
        ..Default::default()
    }))
    .unwrap()
}

fn pixels(device: &wgpu::Device, queue: &wgpu::Queue, texture: &wgpu::Texture) -> Vec<u8> {
    let row = (texture.width() * 4).div_ceil(256) * 256;
    let buffer = device.create_buffer(&wgpu::BufferDescriptor {
        label: None,
        size: u64::from(row * texture.height()),
        usage: wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
        mapped_at_creation: false,
    });
    let mut encoder = device.create_command_encoder(&Default::default());
    encoder.copy_texture_to_buffer(
        texture.as_image_copy(),
        wgpu::TexelCopyBufferInfo {
            buffer: &buffer,
            layout: wgpu::TexelCopyBufferLayout {
                offset: 0,
                bytes_per_row: Some(row),
                rows_per_image: None,
            },
        },
        texture.size(),
    );
    queue.submit(Some(encoder.finish()));
    let (tx, rx) = std::sync::mpsc::channel();
    buffer
        .slice(..)
        .map_async(wgpu::MapMode::Read, move |r| tx.send(r).unwrap());
    device.poll(wgpu::PollType::wait_indefinitely()).unwrap();
    rx.recv().unwrap().unwrap();
    buffer.slice(..).get_mapped_range().unwrap().to_vec()
}

/// Run explicitly on a machine with a Vulkan/Metal/DX12 adapter.
#[test]
#[ignore = "requires a GPU adapter"]
fn peak_tail_line_mode_reset_and_cache() {
    let (device, queue) = device();
    let buffer = PlotBuffer::new(1, 32768);
    let mut data = vec![0.0; 32768];
    data[500] = 0.8; // First column's tail: beyond the old 256-iteration limit.
    buffer.push_batch(&data);
    let mut renderer = PlotRenderer::new(
        &device,
        &queue,
        PlotConfig {
            num_channels: 1,
            capacity: 32768,
            y_min: -1.0,
            y_max: 1.0,
            auto_range: false,
            channel_colors: vec![[1.0, 0.0, 0.0, 1.0]],
        },
    );
    let texture = renderer.render(&buffer, 64, 64, 32768, 0, 1.0).texture;
    let peak = pixels(&device, &queue, &texture);
    assert!(peak[6 * 256 + 3] > 128, "peak beyond sample 256 must remain visible");
    let texture = renderer.render(&buffer, 64, 64, 32768, u32::MAX, 1.0).texture;
    assert_eq!(
        peak,
        pixels(&device, &queue, &texture),
        "pan must clamp to available history"
    );
    buffer.clear();
    let texture = renderer.render(&buffer, 64, 64, 32768, 0, 1.0).texture;
    assert!(
        pixels(&device, &queue, &texture)
            .as_chunks::<4>()
            .0
            .iter()
            .all(|p| p[3] == 0)
    );
    buffer.push_batch(&[0.0, 0.0]);
    let texture = renderer.render(&buffer, 64, 64, 2, 0, 1.0).texture;
    let line = pixels(&device, &queue, &texture);
    assert!(line[32 * 256 + 32 * 4 + 3] > 128);
    let texture = renderer.render(&buffer, 64, 64, 32768, 0, 1.0).texture;
    let sparse = pixels(&device, &queue, &texture);
    assert!(sparse[32 * 256 + 63 * 4 + 3] > 128);
    assert_eq!(sparse[32 * 256 + 3], 0);

    // Projection must use the pixel metric on a wide, non-square plot.
    buffer.clear();
    buffer.push_batch(&[-0.5, 0.5]);
    let texture = renderer.render(&buffer, 320, 64, 2, 0, 1.0).texture;
    let diagonal = pixels(&device, &queue, &texture);
    assert!(diagonal[32 * 1280 + 160 * 4 + 3] > 128);
    assert!(diagonal[35 * 1280 + 160 * 4 + 3] < 16);
}

#[test]
#[ignore = "requires a GPU adapter"]
fn timed_view_preserves_irregular_intervals_precision_and_cache() {
    let (device, queue) = device();
    assert!(device.features().is_empty(), "only core WebGPU features are needed");
    let buffer = PlotBuffer::new(1, 32768);
    let epoch = 1_000_000.0;
    buffer.push_timed_batch(&[epoch, epoch + 0.001, epoch + 0.010], &[0.0, 0.8, 0.0]);
    let mut renderer = PlotRenderer::with_format(
        &device,
        &queue,
        PlotConfig {
            num_channels: 1,
            capacity: 32768,
            y_min: -1.0,
            y_max: 1.0,
            auto_range: false,
            channel_colors: vec![[1.0, 0.0, 0.0, 1.0]],
        },
        wgpu::TextureFormat::Rgba8Unorm,
    );
    let mut view = PlotView {
        width: 320,
        height: 100,
        visible_samples: 3,
        view_offset: 0,
        scale_factor: 1.0,
        x_range: Some([epoch, epoch + 0.010]),
        y_range: Some([-1.0, 1.0]),
    };
    let output = renderer.render_view(&buffer, view);
    assert_eq!((output.y_min, output.y_max), (-1.0, 1.0));
    let image = pixels(&device, &queue, &output.texture);
    let alpha = |x: usize, y: usize| image[y * 1280 + x * 4 + 3];
    assert!(alpha(32, 10) > 64, "peak must be at 10% of the real time range");
    assert!(alpha(160, 10) < 16, "sample index must not determine the X coordinate");
    assert!(alpha(160, 28) > 64);
    assert!(!renderer.render_view(&buffer, view).rendered);
    view.y_range = Some([-2.0, 2.0]);
    assert!(
        renderer.render_view(&buffer, view).rendered,
        "uniform changes must invalidate cache"
    );
    view.x_range = Some([epoch, epoch + 0.005]);
    assert!(renderer.render_view(&buffer, view).rendered);

    buffer.clear();
    buffer.push_timed_batch(&[epoch, epoch + 0.001, epoch + 0.010], &[0.0, f32::NAN, 0.0]);
    let output = renderer.render_view(&buffer, view);
    assert!(
        pixels(&device, &queue, &output.texture)
            .as_chunks::<4>()
            .0
            .iter()
            .all(|p| p[3] == 0)
    );
}

#[test]
#[ignore = "requires a GPU adapter"]
fn timed_compute_reduction_retains_peaks_and_recomputes_when_panning() {
    let (device, queue) = device();
    let buffer = PlotBuffer::new(1, 32768);
    let times: Vec<_> = (0..32768).map(|i| 1_000_000.0 + f64::from(i) * 0.000001).collect();
    let mut data = vec![0.0; times.len()];
    data[500] = 0.8;
    buffer.push_timed_batch(&times, &data);
    let mut renderer = PlotRenderer::with_format(
        &device,
        &queue,
        PlotConfig {
            num_channels: 1,
            capacity: 32768,
            y_min: -1.0,
            y_max: 1.0,
            auto_range: false,
            channel_colors: vec![[1.0, 0.0, 0.0, 1.0]],
        },
        wgpu::TextureFormat::Rgba8Unorm,
    );
    let mut view = PlotView {
        width: 64,
        height: 64,
        visible_samples: 32768,
        view_offset: 0,
        scale_factor: 1.0,
        x_range: Some([times[0], *times.last().unwrap()]),
        y_range: Some([-1.0, 1.0]),
    };
    let output = renderer.render_view(&buffer, view);
    assert!(pixels(&device, &queue, &output.texture)[6 * 256 + 3] > 128);
    assert!(!renderer.render_view(&buffer, view).rendered);
    view.x_range = Some([times[0] - 0.010, times[0] + 0.022767]);
    let output = renderer.render_view(&buffer, view);
    let image = pixels(&device, &queue, &output.texture);
    assert_eq!(image[6 * 256 + 3], 0, "panning must invalidate compute envelopes");
    assert!(image[6 * 256 + 20 * 4 + 3] > 128);
}
