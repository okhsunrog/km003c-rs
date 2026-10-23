use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;

fn main() {
    const IDS_PATH: &str = "data/usb.ids";
    println!("cargo:rerun-if-changed={IDS_PATH}");

    let database = fs::read_to_string(IDS_PATH).expect("read vendored usb.ids");
    let mut vendors = Vec::new();
    for (line_index, line) in database.lines().enumerate() {
        let bytes = line.as_bytes();
        if bytes.len() < 6
            || bytes[0].is_ascii_whitespace()
            || !bytes[..4].iter().all(u8::is_ascii_hexdigit)
            || !bytes[4].is_ascii_whitespace()
        {
            continue;
        }
        let name = line[4..].trim();
        if name.is_empty() {
            continue;
        }
        let id = u16::from_str_radix(&line[..4], 16)
            .unwrap_or_else(|error| panic!("invalid vendor ID on usb.ids line {}: {error}", line_index + 1));
        vendors.push((id, name));
    }

    assert!(!vendors.is_empty(), "usb.ids contains no vendor records");
    for pair in vendors.windows(2) {
        assert!(
            pair[0].0 < pair[1].0,
            "usb.ids vendor IDs are duplicate or unsorted around 0x{:04X}",
            pair[1].0
        );
    }

    let mut generated = String::from(
        "// Generated from data/usb.ids by build.rs.\n\
         static USB_VENDOR_NAMES: &[(u16, &str)] = &[\n",
    );
    for (id, name) in vendors {
        writeln!(generated, "    (0x{id:04X}, {name:?}),").expect("write generated vendor table");
    }
    generated.push_str("];\n");

    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").expect("Cargo sets OUT_DIR"));
    fs::write(out_dir.join("usb_vendors.rs"), generated).expect("write generated USB vendor table");
}
