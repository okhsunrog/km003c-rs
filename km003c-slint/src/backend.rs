//! Launch choices shared by normal runs and display-free MCP inspection.

pub fn is_headless(backend: Option<&str>) -> bool {
    backend.is_some_and(|name| {
        name.split('-')
            .next()
            .is_some_and(|name| name.eq_ignore_ascii_case("headless"))
    })
}

pub fn auto_connect(setting: Option<&str>) -> bool {
    !setting.is_some_and(|value| value == "0" || value.eq_ignore_ascii_case("false"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headless_rasterizers_bypass_the_gpu_requirement() {
        for name in [
            "headless",
            "headless-software",
            "HEADLESS-SKIA",
            "headless-skia-software",
        ] {
            assert!(is_headless(Some(name)), "{name}");
        }
        for name in [
            None,
            Some(""),
            Some("winit-skia"),
            Some("linuxkms"),
            Some("headlessish"),
        ] {
            assert!(!is_headless(name), "{name:?}");
        }
    }

    #[test]
    fn inspection_can_disable_device_discovery_without_changing_normal_startup() {
        assert!(auto_connect(None));
        assert!(auto_connect(Some("1")));
        assert!(!auto_connect(Some("0")));
        assert!(!auto_connect(Some("FALSE")));
    }
}
