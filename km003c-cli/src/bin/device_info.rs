use km003c_lib::{DeviceConfig, KM003C};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Connecting to POWER-Z KM003C...");
    // MemoryRead requires vendor interface (interface 0), not HID
    let mut device = KM003C::with_config(DeviceConfig::vendor_interface()).await?;
    println!("Connected!\n");

    let info = device.get_device_info().await?;

    println!("============================================================");
    println!("DEVICE INFORMATION");
    println!("============================================================");
    println!("Model:              {}", info.model);
    println!("Hardware Version:   {}", info.hw_version);
    println!("Manufacturing Date: {}", info.mfg_date);
    println!();
    println!("Firmware Version:   {}", info.fw_version);
    println!("Firmware Date:      {}", info.fw_date);
    println!();
    println!("Serial ID:          {}", info.serial_id);
    println!("UUID:               {}", info.uuid);
    println!();
    println!("Device Serial:      {}", info.device_serial);

    Ok(())
}
