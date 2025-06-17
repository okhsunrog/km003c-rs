use pcap::{Device, Capture};

fn main() {
    // 1. Find the device named "usbmon3"
    // We use .expect() for a minimal example, but in real code, you should handle errors gracefully.
    let main_device = Device::list()
        .expect("Failed to list devices")
        .into_iter()
        .find(|d| d.name == "usbmon3")
        .expect("usbmon3 device not found. Is the module loaded and do you have permissions?");

    println!("Found device: {:?}", main_device.desc);

    // 2. Open a capture handle on the device.
    // In a real application, you would configure the capture (e.g., with .promisc())
    // before calling .open(). We use .expect() again for simplicity.
    let mut cap = Capture::from_device(main_device)
        .expect("Failed to create capture from device")
        .open()
        .expect("Failed to open capture");

    println!("\nCapturing on usbmon3... Press Ctrl+C to stop.");

    // 3. Loop and print packets.
    // The `next_packet()` method will wait for the next packet to arrive.
    while let Ok(packet) = cap.next_packet() {
        // The `Packet` struct derives `Debug`, so we can print it directly.
        println!("{:?}", packet);
    }
}