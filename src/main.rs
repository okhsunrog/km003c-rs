use nusb::{Interface, transfer::RequestBuffer};
use tracing::{error, info, warn};
use tracing_subscriber;

const KM003C_VID: u16 = 0x5FC9;
const KM003C_PID: u16 = 0x0063;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    info!(
        "Searching for POWER-Z KM003C (VID: {:#06x}, PID: {:#06x})...",
        KM003C_VID, KM003C_PID
    );

    let Some(device_info) = nusb::list_devices()
        .unwrap()
        .find(|d| d.vendor_id() == KM003C_VID && d.product_id() == KM003C_PID)
    else {
        warn!("POWER-Z KM003C not found.");
        return;
    };

    info!("POWER-Z KM003C Found!");

    let device = device_info.open().expect("Failed to open device");
    let interface_number = 0;

    // This is the correct method for Linux to handle kernel drivers.
    // It detaches the driver (if any) and claims the interface in one step.
    info!(
        "Attempting to detach kernel driver and claim Interface #{}",
        interface_number
    );
    match device.detach_and_claim_interface(interface_number) {
        Ok(interface) => {
            info!("Interface #{} claimed successfully.", interface_number);
            run_communication(&interface).await;
            info!(
                "Communication finished. Interface and kernel driver will be handled automatically when program ends."
            );
        }
        Err(e) => {
            error!(
                "Could not detach and claim interface #{}: {:?}",
                interface_number, e
            );
            error!(
                "Please ensure your udev rule is correct (with TAG+='uaccess') and has been reloaded."
            );
        }
    }
}

/// This function handles the actual data transfer with the device.
async fn run_communication(interface: &Interface) {
    // --- Define the Command and Endpoints ---
    let command_to_send = vec![0x0C, 0x00, 0x02, 0x00];

    // From the initial device enumeration:
    // Interface 0, USER/WINUSB
    let out_endpoint = 0x01;
    let in_endpoint = 0x81;

    info!(
        "Sending GET_STATUS command: {:02x?} to endpoint {:#04x}",
        command_to_send, out_endpoint
    );

    // --- Step 1: Write the command ---
    // The `bulk_out` method takes a Vec<u8> and returns a TransferFuture.
    let write_future = interface.bulk_out(out_endpoint, command_to_send);

    // We use .await to wait for the asynchronous operation to complete.
    match write_future.await.into_result() {
        Ok(_) => {
            info!("Successfully wrote command.");

            // --- Step 2: Read the response ---
            // The `bulk_in` method takes a RequestBuffer (which can be created from a length)
            // and returns a TransferFuture. We ask for up to 64 bytes.
            let read_future = interface.bulk_in(in_endpoint, RequestBuffer::new(64));

            info!(
                "Waiting to read response from Endpoint #{:#04x}...",
                in_endpoint
            );
            match read_future.await.into_result() {
                Ok(data) => {
                    info!("SUCCESS! Received {} bytes.", data.len());
                    if !data.is_empty() {
                        let response_hex = data
                            .iter()
                            .map(|b| format!("{:02x}", b))
                            .collect::<Vec<String>>()
                            .join(" ");
                        info!("Response data: [{}]", response_hex);
                        info!("Communication with KM003C is working!");
                    } else {
                        warn!("Received 0 bytes, but the read was successful.");
                    }
                }
                Err(e) => {
                    error!("Failed to read from IN endpoint: {:?}", e);
                }
            }
        }
        Err(e) => {
            error!("Failed to write to OUT endpoint: {:?}", e);
        }
    }
}
