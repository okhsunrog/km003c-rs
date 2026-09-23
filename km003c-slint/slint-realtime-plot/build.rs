fn main() {
    // Mark the UI file as an input — consumers import it via
    // `with_library_paths` (see the demo crate's build.rs).
    println!("cargo::rerun-if-changed=ui/plot.slint");
}
