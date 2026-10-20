//! GPU-accelerated real-time plotting for Slint via WGPU.
//!
//! Rust side: [`PlotBuffer`] — a consistent ring buffer to feed samples
//! into (from any thread), and [`PlotRenderer`] — renders one chart into a
//! texture inside Slint's rendering notifier. Configure the Slint backend
//! with [`required_wgpu_settings`].
//!
//! UI side: `ui/plot.slint` exports the `PlotWidget` component (grid, axes,
//! legend, pan/zoom, cursor). Map it in your `build.rs`:
//!
//! ```ignore
//! # use std::collections::HashMap;
//! let mut library_paths = HashMap::new();
//! library_paths.insert(
//!     "slint-realtime-plot".to_string(),
//!     std::path::PathBuf::from("path/to/slint-realtime-plot/ui"),
//! );
//! slint_build::compile_with_config(
//!     "ui/app.slint",
//!     slint_build::CompilerConfiguration::new().with_library_paths(library_paths),
//! ).unwrap();
//! ```
//!
//! then import it with `import { PlotWidget } from "@slint-realtime-plot/plot.slint";`.

pub use realtime_plot::{MAX_CHANNELS, PlotBuffer, PlotConfig, PlotRenderer, RenderOutput};

use slint::wgpu_30::WGPUSettings;

/// Configure Slint's device for the shared WebGPU-compatible plot renderer.
pub fn required_wgpu_settings(max_capacity: usize, max_channels: usize) -> WGPUSettings {
    let mut settings = WGPUSettings::default();
    settings.device_required_limits = realtime_plot::required_wgpu_limits(max_capacity, max_channels);
    settings
}
