use km003c_lib::{DeviceConfig, KM003C, Packet};
use std::collections::BTreeMap;
use std::time::Duration;

/// Result of a memory read attempt
#[derive(Debug, Clone)]
enum ReadResult {
    Reject,
    NotReadable,
    Data(usize),
    Timeout,
    Error(String),
}

impl std::fmt::Display for ReadResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReadResult::Reject => write!(f, "Reject"),
            ReadResult::NotReadable => write!(f, "NotReadable"),
            ReadResult::Data(size) => write!(f, "Data({}B)", size),
            ReadResult::Timeout => write!(f, "Timeout"),
            ReadResult::Error(e) => write!(f, "Error({})", e),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    println!("KM003C Memory Scanner");
    println!("=====================\n");

    // Connect with no-reset to avoid disturbing the device too much
    let config = DeviceConfig::vendor().skip_reset();
    let mut device = KM003C::new(config).await?;

    let state = device.state().expect("device initialized");
    println!("{}\n", state);

    // Track results by address
    let mut results: BTreeMap<u32, ReadResult> = BTreeMap::new();

    // First, test known addresses from the docs
    println!("Testing known addresses from documentation...\n");

    let known_addresses: &[(u32, u32, &str)] = &[
        (0x00000420, 64, "DeviceInfo1"),
        (0x00004420, 64, "FirmwareInfo"),
        (0x03000C00, 64, "CalibrationData"),
        (0x40010450, 12, "HardwareID"),
        (0x98100000, 64, "LogData"),
    ];

    for (addr, size, name) in known_addresses {
        let result = try_read(&mut device, *addr, *size).await;
        println!("  0x{:08X} ({:16}): {}", addr, name, result);
        results.insert(*addr, result);
        // Small delay to avoid overwhelming the device
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    println!("\n\nScanning memory regions...\n");

    // Scan interesting boundaries
    let boundary_addresses: &[u32] = &[
        0x00000000, 0x00000100, 0x00000200, 0x00000400, 0x00000800, 0x00001000, 0x00002000, 0x00004000, 0x00008000,
        0x00010000, 0x00100000, 0x01000000, 0x02000000, 0x03000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000,
        0x40000000, 0x40010000, 0x40020000, 0x80000000, 0x90000000, 0x98000000, 0x9F000000, 0xA0000000, 0xE0000000,
        0xF0000000, 0xFFFFFF00,
    ];

    for addr in boundary_addresses {
        if results.contains_key(addr) {
            continue;
        }
        let result = try_read(&mut device, *addr, 64).await;
        println!("  0x{:08X}: {}", addr, result);
        results.insert(*addr, result);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Detailed scan around HardwareID region
    println!("\n\nDetailed scan around HardwareID (0x40010000-0x40011000)...\n");

    for offset in (0..0x1000).step_by(0x100) {
        let addr = 0x40010000 + offset;
        if results.contains_key(&addr) {
            continue;
        }
        let result = try_read(&mut device, addr, 16).await;
        if !matches!(result, ReadResult::NotReadable) {
            println!("  0x{:08X}: {}", addr, result);
        }
        results.insert(addr, result);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Detailed scan around calibration region
    println!("\n\nDetailed scan around calibration (0x03000000-0x03002000)...\n");

    for offset in (0..0x2000).step_by(0x100) {
        let addr = 0x03000000 + offset;
        if results.contains_key(&addr) {
            continue;
        }
        let result = try_read(&mut device, addr, 16).await;
        if !matches!(result, ReadResult::NotReadable) {
            println!("  0x{:08X}: {}", addr, result);
        }
        results.insert(addr, result);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Summary
    println!("\n\n=== SUMMARY ===\n");

    let mut reject_count = 0;
    let mut not_readable_count = 0;
    let mut data_count = 0;
    let mut timeout_count = 0;
    let mut error_count = 0;

    for result in results.values() {
        match result {
            ReadResult::Reject => reject_count += 1,
            ReadResult::NotReadable => not_readable_count += 1,
            ReadResult::Data(_) => data_count += 1,
            ReadResult::Timeout => timeout_count += 1,
            ReadResult::Error(_) => error_count += 1,
        }
    }

    println!("Total addresses scanned: {}", results.len());
    println!("  Data:        {}", data_count);
    println!("  NotReadable: {}", not_readable_count);
    println!("  Reject:      {}", reject_count);
    println!("  Timeout:     {}", timeout_count);
    println!("  Error:       {}", error_count);

    println!("\n\nAddresses that returned data:\n");
    for (addr, result) in &results {
        if matches!(result, ReadResult::Data(_)) {
            println!("  0x{:08X}: {}", addr, result);
        }
    }

    Ok(())
}

async fn try_read(device: &mut KM003C, address: u32, size: u32) -> ReadResult {
    // Send MemoryRead request
    if let Err(e) = device.send(Packet::MemoryRead { address, size }).await {
        return ReadResult::Error(format!("send: {}", e));
    }

    // Wait for confirmation packet (0xC4 = Accept) or error response
    match tokio::time::timeout(Duration::from_millis(500), device.receive()).await {
        Ok(Ok(packet)) => match packet {
            Packet::Accept { .. } => {
                // Accept means confirmation received, now get encrypted data
                // receive_memory_read_data() handles decryption
                match tokio::time::timeout(Duration::from_millis(500), device.receive_memory_read_data()).await {
                    Ok(Ok(Packet::MemoryReadResponse { data })) => ReadResult::Data(data.len()),
                    Ok(Ok(other)) => ReadResult::Error(format!("unexpected after confirm: {:?}", other)),
                    Ok(Err(e)) => ReadResult::Error(format!("data recv: {}", e)),
                    Err(_) => ReadResult::Timeout,
                }
            }
            Packet::NotReadable { .. } => ReadResult::NotReadable,
            Packet::Reject { .. } => ReadResult::Reject,
            other => ReadResult::Error(format!("unexpected: {:?}", other)),
        },
        Ok(Err(e)) => ReadResult::Error(format!("recv: {}", e)),
        Err(_) => ReadResult::Timeout,
    }
}
