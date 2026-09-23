use std::collections::HashMap;
use std::path::PathBuf;

fn main() {
    // Map the `@slint-realtime-plot` import prefix to the vendored plot
    // library's ui/ directory, and `@material` to the vendored Material 3
    // component set.
    let manifest = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let library_paths = HashMap::from([
        ("slint-realtime-plot".to_string(), manifest.join("slint-realtime-plot/ui")),
        ("material".to_string(), manifest.join("material/material.slint")),
    ]);
    slint_build::compile_with_config(
        "ui/app.slint",
        slint_build::CompilerConfiguration::new().with_library_paths(library_paths),
    )
    .unwrap();
}
