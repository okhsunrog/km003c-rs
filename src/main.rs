use nusb::list_devices;
use tracing::info;
use tracing_subscriber;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let devices = list_devices().unwrap();
    for device in devices {
        info!("Found USB device: {:?}", device);
    }
}