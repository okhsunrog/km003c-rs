use clap::Parser;
use km003c_lib::{DeviceConfig, GraphSampleRate, KM003C};
use std::error::Error;
use std::time::Duration;

/// AdcQueue streaming example for POWER-Z KM003C
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Sample rate: 2, 10, 50, or 1000 SPS
    #[arg(short, long, default_value = "50", value_parser = ["2", "10", "50", "1000"])]
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
        "2" => GraphSampleRate::Sps2,
        "10" => GraphSampleRate::Sps10,
        "50" => GraphSampleRate::Sps50,
        "1000" => GraphSampleRate::Sps1000,
        _ => unreachable!(),
    };

    // Select interface - AdcQueue requires vendor interface (Full mode)
    let mut config = match args.interface.as_str() {
        "vendor" => DeviceConfig::vendor(),
        "hid" => {
            eprintln!("Warning: HID interface doesn't support AdcQueue streaming.");
            eprintln!("         Use --interface vendor for AdcQueue.");
            return Err("AdcQueue requires vendor interface".into());
        }
        _ => unreachable!(),
    };

    if args.no_reset {
        config = config.skip_reset();
    }

    println!("Connecting to POWER-Z KM003C...");
    let mut device = KM003C::new(config).await?;

    // Check authentication (state is always available after with_config)
    if !device.adcqueue_enabled() {
        return Err("Authentication failed - AdcQueue not enabled".into());
    }

    let state = device.state().expect("device initialized");
    println!("  Device: {} (FW {})", state.info.model, state.info.fw_version);
    println!("  Hardware ID: {}", state.hardware_id);
    println!(
        "  Auth: level={}, adcqueue={}",
        state.auth_level, state.adcqueue_enabled
    );

    // Helper to send command and optionally read response (for raw commands)
    async fn send_and_recv(device: &mut KM003C, data: &[u8], timeout_ms: u64) -> Option<Vec<u8>> {
        if let Err(e) = device.send_raw(data).await {
            eprintln!("Send error: {:?}", e);
            return None;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        match tokio::time::timeout(Duration::from_millis(timeout_ms), device.receive_raw()).await {
            Ok(Ok(data)) => Some(data),
            _ => None,
        }
    }

    // Drain any remaining responses
    while let Ok(Ok(data)) = tokio::time::timeout(Duration::from_millis(100), device.receive_raw()).await {
        println!(
            "    Drained {} bytes (type=0x{:02x})",
            data.len(),
            data.first().map(|b| b & 0x7F).unwrap_or(0)
        );
    }

    println!("Init complete!\n");

    // ================================================================
    // Now start graph mode
    // ================================================================

    // StartGraph at specified rate (tid=0x09)
    // Rate encoding: rate_index sent directly (0=2SPS, 1=10SPS, 2=50SPS, 3=1000SPS)
    let rate_index = rate as u16;
    println!(
        "Starting AdcQueue streaming at {} SPS (rate_index={})...",
        args.rate, rate_index
    );

    let start_cmd = [0x0E, 0x09, (rate_index & 0xFF) as u8, ((rate_index >> 8) & 0xFF) as u8];
    println!("  Sending: {:02x?}", start_cmd);
    let resp = send_and_recv(&mut device, &start_cmd, 2000).await;

    match &resp {
        Some(data) => {
            let pkt_type = data.first().map(|b| b & 0x7F).unwrap_or(0);
            println!(
                "  Response: {} bytes, type=0x{:02x}, data={:02x?}",
                data.len(),
                pkt_type,
                &data[..data.len().min(16)]
            );
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

    // Brief warmup - start polling quickly to avoid large initial batch
    let warmup_ms: u64 = 200;
    println!("Brief warmup {}ms...\n", warmup_ms);
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
    let mut seq_stride: Option<u16> = None; // Detected stride between samples
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
            // Don't sleep - immediately request again
            continue;
        }

        let pkt_type = data[0] & 0x7F;
        if pkt_type != 0x41 {
            if args.verbose {
                println!("DEBUG: Unexpected packet type: 0x{:02x}", pkt_type);
            }
            // Don't sleep - immediately request again
            continue;
        }

        // Check if it's AdcQueue data (attr=2 in extended header)
        let attr = (data[4] as u16) | (((data[5] & 0x7F) as u16) << 8);
        if attr != 2 {
            if args.verbose {
                println!("DEBUG: Got attr={} instead of AdcQueue(2)", attr);
            }
            // Don't sleep - immediately request again
            continue;
        }

        // Parse AdcQueue samples (payload starts at byte 8, 20 bytes per sample)
        let payload = &data[8..];
        let num_samples = payload.len() / 20;

        if num_samples == 0 {
            // Empty response - wait a bit for samples to accumulate
            tokio::time::sleep(Duration::from_millis(20)).await;
            continue;
        }

        packet_count += 1;

        // Debug: show packet info
        if args.verbose {
            let first_seq = u16::from_le_bytes([payload[0], payload[1]]);
            let last_seq = if num_samples > 1 {
                let last_offset = (num_samples - 1) * 20;
                u16::from_le_bytes([payload[last_offset], payload[last_offset + 1]])
            } else {
                first_seq
            };
            println!(
                "DEBUG: Packet {} - {} bytes, {} samples, seq {}..{}",
                packet_count,
                data.len(),
                num_samples,
                first_seq,
                last_seq
            );
        }

        // Print interval based on rate
        let print_interval = match rate {
            GraphSampleRate::Sps2 | GraphSampleRate::Sps10 => 1,
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

            // Detect stride from consecutive samples in same packet
            if let Some(last) = last_seq {
                if i > 0 && seq_stride.is_none() {
                    // Detect stride from consecutive samples within this packet
                    let detected = seq.wrapping_sub(last);
                    seq_stride = Some(detected);
                    if args.verbose {
                        println!("DEBUG: Detected seq stride = {}", detected);
                    }
                }

                // Check for dropped samples using detected stride
                if i == 0 {
                    let stride = seq_stride.unwrap_or(20); // Default 20 if not yet detected
                    let expected = last.wrapping_add(stride);
                    if seq != expected {
                        let gap = seq.wrapping_sub(last);
                        let dropped = gap.saturating_sub(stride) / stride;
                        if dropped > 0 {
                            println!("Warning: {} samples dropped (gap={})", dropped, gap);
                        }
                    }
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

        // Drain any queued unsolicited responses (PD events etc.) before sleeping
        while let Ok(Ok(drain_data)) = tokio::time::timeout(Duration::from_millis(5), device.receive_raw()).await {
            if args.verbose {
                let drain_type = drain_data.first().map(|b| b & 0x7F).unwrap_or(0);
                println!("DEBUG: Drained {} bytes type=0x{:02x}", drain_data.len(), drain_type);
            }
        }

        // Minimal delay - device needs time to buffer samples
        // At 50 SPS, 20ms is 1 sample period. 40ms should give ~2 samples per request
        tokio::time::sleep(Duration::from_millis(40)).await;
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
