use nusb::list_devices;
use tracing::info;
use tracing_subscriber;

#[tokio::main]
async fn main() {
    // Initialize tracing (optional, but good for debugging)
    tracing_subscriber::fmt::init();

    info!("Listing connected USB devices...\n");

    match list_devices() {
        Ok(devices) => {
            let mut count = 0;
            for device_info in devices {
                count += 1;
                // DeviceInfo struct already has optional manufacturer_string, product_string, serial_number
                info!(
                    "Device #{}: VID: {:#06x}, PID: {:#06x}, Bus: {:03}, Address: {:03}",
                    count,
                    device_info.vendor_id(),
                    device_info.product_id(),
                    device_info.bus_number(),
                    device_info.device_address()
                );
                if let Some(manufacturer) = device_info.manufacturer_string() {
                    info!("  Manufacturer: {}", manufacturer);
                } else {
                    info!("  Manufacturer: <Not available>");
                }
                if let Some(product) = device_info.product_string() {
                    info!("  Product: {}", product);
                } else {
                    info!("  Product: <Not available>");
                }
                if let Some(serial) = device_info.serial_number() {
                    info!("  Serial: {}", serial);
                } else {
                    info!("  Serial: <Not available>");
                }
                info!("  Speed: {:?}", device_info.speed());
                info!("  Raw DeviceInfo: {:?}", device_info); // For all details
                info!("---");
            }
            if count == 0 {
                info!("No USB devices found.");
            }
        }
        Err(e) => {
            eprintln!("Error listing USB devices: {:?}", e);
        }
    }
}