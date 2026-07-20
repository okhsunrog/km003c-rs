use km003c_lib::uom::si::ratio::percent;
use km003c_lib::uom::si::time::microsecond;
use km003c_lib::{DeviceConfig, KM003C};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut device = KM003C::new(DeviceConfig::vendor().skip_reset()).await?;
    let settings = device.request_settings().await?;

    println!("Device name: {}", settings.device_name().unwrap_or("<invalid UTF-8>"));
    println!("Language selection: {}", settings.language_selection());
    println!("Uncalibrated: {}", settings.is_uncalibrated());
    println!("Brightness: {}%", settings.brightness().get::<percent>());
    println!(
        "Sample interval: {} us",
        settings.sample_interval().get::<microsecond>()
    );
    println!("Screen orientation: {}", settings.screen_orientation());
    println!("Mtools device mode: {}", settings.mtools_device_mode());
    println!("Selected main page: {}", settings.selected_main_page());

    Ok(())
}
