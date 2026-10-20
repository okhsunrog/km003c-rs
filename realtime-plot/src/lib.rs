//! UI-independent real-time plotting into a GPU texture.
//!
//! Both frontends share the ring buffer, incremental uploads, compute min/max
//! reduction and anti-aliased line shaders. Only core WebGPU features are used.

mod buffer;
mod renderer;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod gpu_tests;

pub use buffer::PlotBuffer;
pub use renderer::{PlotConfig, PlotRenderer, PlotView, RenderOutput};
pub use wgpu;

/// Maximum number of channels supported by the shaders.
pub const MAX_CHANNELS: usize = 8;

/// Device limits needed for the largest chart used by a frontend.
/// No optional GPU features (including immediates) are required.
pub fn required_wgpu_limits(max_capacity: usize, max_channels: usize) -> wgpu::Limits {
    assert!((1..=MAX_CHANNELS).contains(&max_channels));
    let storage_size = (max_capacity as u64 * max_channels as u64 * 4)
        .max(max_capacity as u64 * 8)
        .max(32768 * max_channels as u64 * 16);
    wgpu::Limits {
        max_compute_invocations_per_workgroup: 64,
        max_compute_workgroup_size_x: 64,
        max_compute_workgroup_size_y: 1,
        max_compute_workgroup_size_z: 1,
        max_storage_buffers_per_shader_stage: 3,
        max_storage_buffer_binding_size: storage_size,
        max_buffer_size: storage_size.max(wgpu::Limits::default().max_buffer_size),
        ..Default::default()
    }
}
