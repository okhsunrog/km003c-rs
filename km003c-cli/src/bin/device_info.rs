use km003c_lib::{DeviceConfig, KM003C};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Connecting to POWER-Z KM003C...");

    // Connect with vendor interface for Full mode (device info requires init)
    let device = KM003C::new(DeviceConfig::vendor()).await?;

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
