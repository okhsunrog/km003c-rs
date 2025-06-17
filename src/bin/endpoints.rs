use nusb::list_devices;
use nusb::transfer::EndpointType; // Corrected import based on provided docs
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

    match list_devices() {
        Ok(devices_iter) => {
            let km003c_device_info = devices_iter
                .into_iter()
                .find(|d| d.vendor_id() == KM003C_VID && d.product_id() == KM003C_PID);

            if let Some(device_info) = km003c_device_info {
                info!("POWER-Z KM003C Found!");
                info!(
                    "  VID: {:#06x}, PID: {:#06x}, Bus: {:03}, Address: {:03}",
                    device_info.vendor_id(),
                    device_info.product_id(),
                    device_info.bus_number(),
                    device_info.device_address()
                );
                if let Some(manufacturer) = device_info.manufacturer_string() {
                    info!("  Manufacturer: {}", manufacturer);
                }
                if let Some(product) = device_info.product_string() {
                    info!("  Product: {}", product);
                }
                if let Some(serial) = device_info.serial_number() {
                    info!("  Serial: {}", serial);
                }
                info!("  Speed: {:?}", device_info.speed());

                let interfaces_vec: Vec<_> = device_info.interfaces().cloned().collect();
                info!(
                    "  Interfaces reported by DeviceInfo (summary): {:?}",
                    interfaces_vec
                );

                match device_info.open() {
                    Ok(device_handle) => {
                        info!("\nDevice Opened. Inspecting active configuration and endpoints:");

                        match device_handle.active_configuration() {
                            Ok(active_config) => {
                                info!(
                                    "  Active Configuration Value (bConfigurationValue): {}",
                                    active_config.configuration_value()
                                );
                                info!(
                                    "  Max Power: {} mA",
                                    active_config.max_power() as u16 * 2
                                );
                                let attributes = active_config.attributes();
                                let is_self_powered = (attributes & 0x40) != 0;
                                let can_remote_wakeup = (attributes & 0x20) != 0;
                                info!("  Attributes (bmAttributes): {:#04x}", attributes);
                                info!("    Self Powered: {}", is_self_powered);
                                info!("    Remote Wakeup: {}", can_remote_wakeup);

                                info!(
                                    "    Number of Interface Groups in active config: {}",
                                    active_config.interfaces().count()
                                );

                                for interface_group in active_config.interfaces() {
                                    info!("    -----------------------------------");
                                    // Iterate over InterfaceAltSettings within this group
                                    for setting_desc in interface_group.alt_settings() {
                                        info!(
                                            "      Interface Number: {}",
                                            setting_desc.interface_number()
                                        );
                                        info!(
                                            "      Alternate Setting: {}",
                                            setting_desc.alternate_setting()
                                        );
                                        info!(
                                            "        Interface Class: {:#04x}",
                                            setting_desc.class()
                                        );
                                        info!(
                                            "        Interface SubClass: {:#04x}",
                                            setting_desc.subclass()
                                        );
                                        info!(
                                            "        Interface Protocol: {:#04x}",
                                            setting_desc.protocol()
                                        );
                                        // Corrected method name: string_index
                                        if let Some(if_string_idx) = setting_desc.string_index() {
                                            // Fetching the string descriptor:
                                            // use std::time::Duration;
                                            // const DEFAULT_LANGUAGE_ID: u16 = 0x0409;
                                            // const STRING_FETCH_TIMEOUT: Duration = Duration::from_millis(100);
                                            // match device_handle.get_string_descriptor(if_string_idx, DEFAULT_LANGUAGE_ID, STRING_FETCH_TIMEOUT) {
                                            //     Ok(s) => info!("        Interface String: {}", s),
                                            //     Err(_) => info!("        Interface String Index: {} (fetch failed or no string for lang)", if_string_idx),
                                            // }
                                            info!("        Interface String Index: {}", if_string_idx);
                                        } else {
                                            info!("        Interface String Index: None");
                                        }

                                        info!(
                                            "        Endpoints in this setting: {}",
                                            setting_desc.endpoints().count()
                                        );
                                        for endpoint_desc in setting_desc.endpoints() {
                                            let ep_addr = endpoint_desc.address();
                                            // Corrected direction check: Bit 7 (0x80) for IN
                                            let direction = if (ep_addr & 0x80) != 0 { "IN" } else { "OUT" };
                                            // Corrected transfer type matching
                                            let transfer_type_str =
                                                match endpoint_desc.transfer_type() {
                                                    EndpointType::Control => "Control",
                                                    EndpointType::Isochronous => "Isochronous",
                                                    EndpointType::Bulk => "Bulk",
                                                    EndpointType::Interrupt => "Interrupt",
                                                };
                                            info!(
                                                // Corrected address: just ep_addr, or ep_addr & 0x7F for number only
                                                "          Endpoint Address: {:#04x} (Number: {:#04x}, Direction: {})",
                                                ep_addr,
                                                ep_addr & 0x7F, // Mask direction bit to get number
                                                direction
                                            );
                                            info!(
                                                "            Transfer Type: {}",
                                                transfer_type_str
                                            );
                                            info!(
                                                "            Max Packet Size: {}",
                                                endpoint_desc.max_packet_size()
                                            );
                                            info!(
                                                "            Interval: {}",
                                                endpoint_desc.interval()
                                            );
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                error!("  Failed to get active configuration: {:?}", e);
                            }
                        }
                    }
                    Err(e) => {
                        error!(
                            "Failed to open KM003C device: {:?}. Check permissions (udev rules on Linux).",
                            e
                        );
                    }
                }
            } else {
                warn!("POWER-Z KM003C not found.");
            }
        }
        Err(e) => {
            error!("Error listing USB devices: {:?}", e);
        }
    }
}