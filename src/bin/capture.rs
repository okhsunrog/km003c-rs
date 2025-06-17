use rtshark::{RTShark, RTSharkBuilder};
use std::process;
use tokio; // tokio is still needed for the #[tokio::main] macro
use tracing::{error, info, warn, Level};
use tracing_subscriber;


#[tokio::main]
async fn main() {
    // Initialize the tracing subscriber.
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_target(false)
        .init();

    // Build the tshark command.
    let builder = RTSharkBuilder::builder()
        .input_path("usbmon3")
        .live_capture()
        .display_filter("usb.device_address == 31 && usb.transfer_type == 0x03");

    info!("Starting tshark live capture on usbmon3...");
    info!("Waiting for USB traffic from device 31...");

    // Spawn tshark as a child process.
    let mut rtshark: RTShark = builder.spawn().unwrap_or_else(|e| {
        error!(error = %e, "Failed to start tshark. Is it installed and in your PATH?");
        process::exit(1);
    });

    // Loop and read from tshark.
    // The .read() method is synchronous/blocking, so no .await is needed.
    while let Some(packet) = rtshark.read().unwrap_or_else(|e| {
        error!(error = %e, "Error parsing tshark output stream.");
        None
    }) {
        let mut direction: Option<u32> = None;
        let mut payload: Option<String> = None;

        if let Some(usb_layer) = packet.layer_name("usb") {
            if let Some(dir_field) = usb_layer.metadata("usb.endpoint_address.direction") {
                direction = dir_field.value().parse().ok();
            }
            if let Some(payload_field) = usb_layer.metadata("usb.capdata") {
                payload = Some(payload_field.value().to_string());
            }
        } else {
            warn!("Received a packet that did not contain a USB layer.");
            continue;
        }

        if let (Some(dir), Some(data)) = (direction, payload) {
            let direction_str = if dir == 0 { "Host -> Device" } else { "Device -> Host" };
            
            info!(
                direction = direction_str,
                bytes = data.len() / 2,
                payload = data,
                "Application data captured"
            );
        }
    }

    info!("tshark process finished.");
}