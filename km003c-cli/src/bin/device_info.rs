use km003c_lib::{auth, KM003C, Packet};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    println!("Connecting to POWER-Z KM003C (vendor interface)...");
    let config = km003c_lib::DeviceConfig::vendor_interface();
    let mut device = KM003C::with_config(config).await?;
    println!("Connected!\n");

    // Send Connect first
    println!("Sending Connect...");
    device.send(Packet::Connect).await?;
    let resp = device.receive().await?;
    println!("  Response: {:?}", resp);

    // Manual test first
    println!("\nTesting manual MemoryRead of DeviceInfo (0x420, 64 bytes)...");
    device
        .send(Packet::MemoryRead {
            address: auth::DEVICE_INFO_ADDRESS,
            size: auth::INFO_BLOCK_SIZE as u32,
        })
        .await?;
    println!("  Sent MemoryRead");

    let confirm = device.receive().await?;
    println!("  Confirmation: {:?}", confirm);

    let data = device.receive_memory_read_data().await?;
    println!("  Data: {:?}", data);

    println!("\nNow trying get_device_info()...");
    let info = device.get_device_info().await?;

    println!("\n============================================================");
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
