use clap::Parser;
use km003c_lib::{DeviceConfig, KM003C};

/// Display POWER-Z KM003C device information
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Skip USB reset (defaults to true on macOS for compatibility)
    #[arg(long, default_value_t = cfg!(target_os = "macos"))]
    no_reset: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    println!("Connecting to POWER-Z KM003C...");

    // Connect with vendor interface for Full mode (device info requires init)
    let mut config = DeviceConfig::vendor();
    if args.no_reset {
        config = config.skip_reset();
    }
    let device = KM003C::new(config).await?;

    // State is always available after new()
    let state = device.state().expect("device initialized");

    println!("============================================================");
    println!("DEVICE INFORMATION");
    println!("============================================================");
    println!("Model:              {}", state.info.model);
    println!("Hardware Version:   {}", state.info.hw_version);
    println!("Manufacturing Date: {}", state.info.mfg_date);
    println!();
    println!("Firmware Version:   {}", state.info.fw_version);
    println!("Firmware Date:      {}", state.info.fw_date);
    println!();
    println!("Serial ID:          {}", state.info.serial_id);
    println!("UUID:               {}", state.info.uuid);
    println!();
    println!("Hardware ID:        {}", state.hardware_id);

    println!();
    println!("============================================================");
    println!("AUTHENTICATION");
    println!("============================================================");
    println!("Auth Level:         {}", state.auth_level);
    println!("Authenticated:      {}", state.is_authenticated());
    println!("AdcQueue Enabled:   {}", state.adcqueue_enabled);

    Ok(())
}
