use clap::Parser;
use km003c_lib::{DeviceConfig, GraphSampleRate, KM003C};
use std::error::Error;
use std::time::Duration;

/// AdcQueue streaming example for POWER-Z KM003C
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Sample rate: 1, 10, 50, or 1000 SPS
    #[arg(short, long, default_value = "50", value_parser = ["1", "10", "50", "1000"])]
    rate: String,

    /// Duration in seconds
    #[arg(short, long, default_value = "10")]
    duration: u64,

    /// USB interface: "vendor" or "hid"
    #[arg(short, long, default_value = "vendor")]
    interface: String,

    /// Verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Skip USB reset (for MacOS compatibility)
    #[arg(long)]
    no_reset: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    // Initialize logging
    let log_level = if args.verbose {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };
    tracing_subscriber::fmt().with_max_level(log_level).init();

    // Parse rate
    let rate = match args.rate.as_str() {
        "1" => GraphSampleRate::Sps1,
        "10" => GraphSampleRate::Sps10,
        "50" => GraphSampleRate::Sps50,
        "1000" => GraphSampleRate::Sps1000,
        _ => unreachable!(),
    };

    // Select interface
    let mut config = match args.interface.as_str() {
        "vendor" => DeviceConfig::vendor_interface(),
        "hid" => DeviceConfig::hid_interface(),
        _ => unreachable!(),
    };

    if args.no_reset {
        config = config.with_skip_reset();
    }

    println!("Connecting to POWER-Z KM003C...");
    let mut device = KM003C::with_config(config).await?;
    println!("Connected\n");

    // ================================================================
    // AdcQueue requires full initialization sequence (unlike simple ADC)
    // This includes Unknown68/76 handshake commands
    // ================================================================
    println!("Running initialization sequence for AdcQueue...");

    // Helper to send command and optionally read response
    async fn send_and_recv(
        device: &mut KM003C,
        data: &[u8],
        timeout_ms: u64,
    ) -> Option<Vec<u8>> {
        if let Err(e) = device.send_raw(data).await {
            eprintln!("Send error: {:?}", e);
            return None;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        match tokio::time::timeout(
            Duration::from_millis(timeout_ms),
            device.receive_raw(),
        )
        .await
        {
            Ok(Ok(data)) => Some(data),
            _ => None,
        }
    }

    // 1. Connect (tid=1)
    print!("  Connect... ");
    let resp = send_and_recv(&mut device, &[0x02, 0x01, 0x00, 0x00], 2000).await;
    if resp.map(|r| r.first().map(|b| b & 0x7F) == Some(0x05)).unwrap_or(false) {
        println!("OK");
    } else {
        println!("FAILED");
        return Err("Connect failed".into());
    }

    // 2. Unknown68 commands (tid=2,3,4,5) - some may timeout, that's OK
    // NOTE: Some commands trigger unsolicited responses that must be drained
    print!("  Unknown68 init... ");
    let cmds68 = [
        hex::decode("4402010133f8860c0054288cdc7e52729826872dd18b539a39c407d5c063d91102e36a9e").unwrap(),
        hex::decode("44030101636beaf3f0856506eee9a27e89722dcfd18b539a39c407d5c063d91102e36a9e").unwrap(),
        hex::decode("44040101c51167ae613a6d46ec84a6bde8bd462ad18b539a39c407d5c063d91102e36a9e").unwrap(),
        hex::decode("440501019c409debc8df53b83b066c315250d05cd18b539a39c407d5c063d91102e36a9e").unwrap(),
    ];
    let mut ok_count = 0;
    for cmd in &cmds68 {
        if let Err(e) = device.send_raw(cmd).await {
            eprintln!("Unknown68 send error: {:?}", e);
            continue;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Read primary response
        match tokio::time::timeout(Duration::from_millis(500), device.receive_raw()).await {
            Ok(Ok(_)) => ok_count += 1,
            _ => {}
        }

        // Drain any unsolicited responses (Type0x40, Type0x75)
        loop {
            match tokio::time::timeout(Duration::from_millis(100), device.receive_raw()).await {
                Ok(Ok(_)) => {} // drained
                _ => break,
            }
        }
    }
    println!("{}/4 OK", ok_count);

    // 3. Unknown76 (tid=6)
    print!("  Unknown76... ");
    let resp = send_and_recv(
        &mut device,
        &hex::decode("4c0600025538815b69a452c83e54ef1d70f3bc9ae6aac1b12a6ac07c20fde58c7bf517ca").unwrap(),
        2000,
    ).await;
    println!("{}", if resp.is_some() { "OK" } else { "timeout" });

    // 4. GetData PD status (tid=7) - ATT_PD_STATUS=0x0020 -> wire=0x0040
    print!("  GetData PD status... ");
    let resp = send_and_recv(&mut device, &[0x0C, 0x07, 0x40, 0x00], 2000).await;
    println!("{}", resp.map(|r| format!("{} bytes", r.len())).unwrap_or("timeout".into()));

    // 5. GetData Settings (tid=8) - ATT_SETTINGS=0x0008 -> wire=0x0010
    print!("  GetData Settings... ");
    let resp = send_and_recv(&mut device, &[0x0C, 0x08, 0x10, 0x00], 2000).await;
    println!("{}", resp.map(|r| format!("{} bytes", r.len())).unwrap_or("timeout".into()));

    // 6. StopGraph cleanup (tid=9)
    print!("  StopGraph cleanup... ");
    let resp = send_and_recv(&mut device, &[0x0F, 0x09, 0x00, 0x00], 500).await;
    println!("{}", if resp.is_some() { "OK" } else { "timeout" });
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Drain any remaining responses
    loop {
        match tokio::time::timeout(Duration::from_millis(100), device.receive_raw()).await {
            Ok(Ok(data)) => {
                println!("    Drained {} bytes (type=0x{:02x})", data.len(), data.first().map(|b| b & 0x7F).unwrap_or(0));
            }
            _ => break,
        }
    }

    println!("Init complete!\n");

    // ================================================================
    // Now start graph mode
    // ================================================================

    // StartGraph at specified rate (tid=0x0A)
    // Rate encoding: rate_index -> wire = rate_index * 2 (shifted by 1)
    let rate_wire = (rate as u16) * 2;
    println!("Starting AdcQueue streaming at {} SPS (rate_wire=0x{:04x})...", args.rate, rate_wire);

    let start_cmd = [0x0E, 0x0A, (rate_wire & 0xFF) as u8, ((rate_wire >> 8) & 0xFF) as u8];
    println!("  Sending: {:02x?}", start_cmd);
    let resp = send_and_recv(&mut device, &start_cmd, 2000).await;

    match &resp {
        Some(data) => {
            let pkt_type = data.first().map(|b| b & 0x7F).unwrap_or(0);
            println!("  Response: {} bytes, type=0x{:02x}, data={:02x?}", data.len(), pkt_type, &data[..data.len().min(16)]);
            if pkt_type == 0x05 {
                println!("Streaming started\n");
            } else if pkt_type == 0x06 {
                println!("StartGraph REJECTED (type=0x06)");
                return Err("StartGraph rejected".into());
            } else {
                println!("Unexpected response type");
            }
        }
        None => {
            println!("  No response (timeout)");
            return Err("StartGraph timeout".into());
        }
    }

    // Wait for samples to accumulate
    let warmup_ms: u64 = 2000;
    println!("Waiting {}ms for buffer to fill...\n", warmup_ms);
    tokio::time::sleep(Duration::from_millis(warmup_ms)).await;

    println!("{}", "=".repeat(90));
    println!(
        "{:>6} {:>10} {:>10} {:>10} {:>8} {:>8} {:>8} {:>8}",
        "Seq", "VBUS", "IBUS", "Power", "CC1", "CC2", "D+", "D-"
    );
    println!(
        "{:>6} {:>10} {:>10} {:>10} {:>8} {:>8} {:>8} {:>8}",
        "", "(V)", "(A)", "(W)", "(V)", "(V)", "(V)", "(V)"
    );
    println!("{}", "=".repeat(90));

    let start_time = std::time::Instant::now();
    let mut total_samples = 0;
    let mut packet_count = 0;
    let mut last_seq: Option<u16> = None;
    let mut tid: u8 = 0x0B;

    while start_time.elapsed() < Duration::from_secs(args.duration) {
        // Request AdcQueue data - ATT_ADC_QUEUE=0x0002 -> wire=0x0004
        tid = tid.wrapping_add(1);
        let request = [0x0C, tid, 0x04, 0x00];

        if let Err(e) = device.send_raw(&request).await {
            if args.verbose {
                println!("DEBUG: Send error: {:?}", e);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        }

        let data = match device.receive_raw().await {
            Ok(d) => d,
            Err(e) => {
                if args.verbose {
                    println!("DEBUG: Receive error: {:?}", e);
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };

        // Parse response
        if data.len() < 8 {
            if args.verbose {
                println!("DEBUG: Short response: {} bytes", data.len());
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
            continue;
        }

        let pkt_type = data[0] & 0x7F;
        if pkt_type != 0x41 {
            if args.verbose {
                println!("DEBUG: Unexpected packet type: 0x{:02x}", pkt_type);
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
            continue;
        }

        // Check if it's AdcQueue data (attr=2 in extended header)
        let attr = (data[4] as u16) | (((data[5] & 0x7F) as u16) << 8);
        if attr != 2 {
            if args.verbose {
                println!("DEBUG: Got attr={} instead of AdcQueue(2)", attr);
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
            continue;
        }

        // Parse AdcQueue samples (payload starts at byte 8, 20 bytes per sample)
        let payload = &data[8..];
        let num_samples = payload.len() / 20;

        if num_samples == 0 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        }

        packet_count += 1;

        // Print interval based on rate
        let print_interval = match rate {
            GraphSampleRate::Sps1 | GraphSampleRate::Sps10 => 1,
            GraphSampleRate::Sps50 => 5,
            GraphSampleRate::Sps1000 => 50,
        };

        for i in 0..num_samples {
            let offset = i * 20;
            let sample = &payload[offset..offset + 20];

            let seq = u16::from_le_bytes([sample[0], sample[1]]);
            let vbus_v = i32::from_le_bytes([sample[4], sample[5], sample[6], sample[7]]) as f64 / 1_000_000.0;
            let ibus_a = i32::from_le_bytes([sample[8], sample[9], sample[10], sample[11]]) as f64 / 1_000_000.0;
            let power_w = vbus_v * ibus_a;
            let cc1_v = u16::from_le_bytes([sample[12], sample[13]]) as f64 / 10_000.0;
            let cc2_v = u16::from_le_bytes([sample[14], sample[15]]) as f64 / 10_000.0;
            let vdp_v = u16::from_le_bytes([sample[16], sample[17]]) as f64 / 10_000.0;
            let vdm_v = u16::from_le_bytes([sample[18], sample[19]]) as f64 / 10_000.0;

            // Check for dropped samples
            if let Some(last) = last_seq {
                let expected = last.wrapping_add(1);
                if i == 0 && seq != expected {
                    let gap = seq.wrapping_sub(last);
                    println!("Warning: {} samples dropped", gap.saturating_sub(1));
                }
            }
            last_seq = Some(seq);

            total_samples += 1;

            if total_samples % print_interval == 1 {
                println!(
                    "{:>6} {:>10.3} {:>10.3} {:>10.3} {:>8.3} {:>8.3} {:>8.3} {:>8.3}",
                    seq, vbus_v, ibus_a, power_w, cc1_v, cc2_v, vdp_v, vdm_v
                );
            }
        }

        // Delay between requests - 200ms is standard polling interval
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    println!("{}", "=".repeat(90));
    println!("\nStopping streaming...");

    // Stop graph mode (tid increments)
    tid = tid.wrapping_add(1);
    let _ = send_and_recv(&mut device, &[0x0F, tid, 0x00, 0x00], 500).await;
    println!("Stopped\n");

    // Statistics
    let elapsed = start_time.elapsed().as_secs_f64();
    let effective_rate = total_samples as f64 / elapsed;

    println!("Statistics:");
    println!("  Duration: {:.1}s", elapsed);
    println!("  Packets received: {}", packet_count);
    println!("  Total samples: {}", total_samples);
    if packet_count > 0 {
        println!(
            "  Average samples/packet: {:.1}",
            total_samples as f64 / packet_count as f64
        );
    }
    println!("  Effective sample rate: {:.1} SPS", effective_rate);
    println!("  Expected rate: {} SPS", args.rate);

    Ok(())
}
