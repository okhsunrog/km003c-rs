use clap::Parser;
use km003c_lib::{
    DeviceConfig, GraphSampleRate, KM003C,
    packet::{Attribute, AttributeSet},
};
use std::error::Error;
use std::time::Duration;
use uom::si::electric_current::ampere;
use uom::si::electric_potential::volt;
use uom::si::f64::Frequency;
use uom::si::frequency::hertz;
use uom::si::power::watt;

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

    /// Verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Skip USB reset (defaults to true on macOS for compatibility)
    #[arg(long, default_value_t = cfg!(target_os = "macos"))]
    no_reset: bool,

    /// Force USB reset even on macOS (overrides --no-reset)
    #[arg(long)]
    reset: bool,
}

#[derive(Debug, Default)]
struct SequenceStatistics {
    previous: Option<u16>,
    intervals: u64,
    elapsed_ticks: u64,
    missing_samples: u64,
}

impl SequenceStatistics {
    fn observe(&mut self, rate: GraphSampleRate, sequence: u16) -> u16 {
        let Some(previous) = self.previous.replace(sequence) else {
            return 0;
        };

        let elapsed_ticks = sequence.wrapping_sub(previous);
        let missing = rate.missing_samples(previous, sequence);
        self.intervals += 1;
        self.elapsed_ticks += u64::from(elapsed_ticks);
        self.missing_samples += u64::from(missing);
        missing
    }

    fn delivered_sample_rate(&self) -> Option<Frequency> {
        (self.elapsed_ticks > 0).then(|| {
            Frequency::new::<hertz>(
                self.intervals as f64 * GraphSampleRate::sequence_counter_frequency().get::<hertz>()
                    / self.elapsed_ticks as f64,
            )
        })
    }
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

    // AdcQueue requires vendor interface (Full mode)
    let mut config = DeviceConfig::vendor();
    if args.no_reset && !args.reset {
        config = config.skip_reset();
    }

    println!("Connecting to POWER-Z KM003C...\n");
    let mut device = KM003C::new(config).await?;

    // Check authentication
    if !device.adcqueue_enabled() {
        return Err("Authentication failed - AdcQueue not enabled".into());
    }

    let state = device.state().expect("device initialized");
    println!("{}\n", state);

    println!("Init complete!\n");

    // Start graph mode using library API
    println!(
        "Starting AdcQueue streaming at {} SPS (rate_index={})...",
        args.rate, rate as u16
    );
    device.start_graph_mode(rate).await?;
    println!("Streaming started\n");

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
    let mut sequence_statistics = SequenceStatistics::default();

    while start_time.elapsed() < Duration::from_secs(args.duration) {
        // Request AdcQueue data using library API
        let mask = AttributeSet::single(Attribute::AdcQueue);
        let packet = match device.request_data(mask).await {
            Ok(p) => p,
            Err(e) => {
                if args.verbose {
                    println!("DEBUG: Request error: {:?}", e);
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };

        // Extract AdcQueue data from the parsed packet
        let queue_data = match packet.get_adc_queue() {
            Some(data) => data,
            None => {
                if args.verbose {
                    println!("DEBUG: No AdcQueue data in response");
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
                continue;
            }
        };

        if queue_data.samples.is_empty() {
            tokio::time::sleep(Duration::from_millis(20)).await;
            continue;
        }

        packet_count += 1;

        if args.verbose
            && let Some((first, last)) = queue_data.sequence_range()
        {
            println!(
                "DEBUG: Packet {} - {} samples, seq {}..{}",
                packet_count,
                queue_data.samples.len(),
                first,
                last
            );
        }

        // Print interval based on rate
        let print_interval = match rate {
            GraphSampleRate::Sps2 | GraphSampleRate::Sps10 => 1,
            GraphSampleRate::Sps50 => 5,
            GraphSampleRate::Sps1000 => 50,
        };

        for sample in &queue_data.samples {
            let previous = sequence_statistics.previous;
            let dropped = sequence_statistics.observe(rate, sample.sequence);
            if dropped > 0 {
                let gap = sample
                    .sequence
                    .wrapping_sub(previous.expect("a gap requires a previous sample"));
                println!("Warning: {} samples dropped (gap={})", dropped, gap);
            }

            total_samples += 1;

            if (total_samples - 1) % print_interval == 0 {
                println!(
                    "{:>6} {:>10.3} {:>10.3} {:>10.3} {:>8.3} {:>8.3} {:>8.3} {:>8.3}",
                    sample.sequence,
                    sample.vbus.get::<volt>(),
                    sample.ibus.get::<ampere>(),
                    sample.power.get::<watt>(),
                    sample.cc1.get::<volt>(),
                    sample.cc2.get::<volt>(),
                    sample.vdp.get::<volt>(),
                    sample.vdm.get::<volt>()
                );
            }
        }

        // Minimal delay - device needs time to buffer samples
        tokio::time::sleep(Duration::from_millis(40)).await;
    }

    println!("{}", "=".repeat(90));
    println!("\nStopping streaming...");

    // Stop graph mode using library API
    device.stop_graph_mode().await?;
    println!("Stopped\n");

    // Statistics
    let elapsed = start_time.elapsed().as_secs_f64();
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
    if let Some(rate) = sequence_statistics.delivered_sample_rate() {
        println!("  Delivered sample rate (device clock): {:.1} SPS", rate.get::<hertz>());
    } else {
        println!("  Delivered sample rate (device clock): insufficient samples");
    }
    println!("  Missing samples: {}", sequence_statistics.missing_samples);
    println!("  Expected rate: {} SPS", args.rate);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequence_rate_uses_device_ticks() {
        let mut statistics = SequenceStatistics::default();
        for sequence in [100, 120, 140] {
            statistics.observe(GraphSampleRate::Sps50, sequence);
        }

        assert_eq!(statistics.delivered_sample_rate().unwrap().get::<hertz>(), 50.0);
        assert_eq!(statistics.missing_samples, 0);
    }

    #[test]
    fn sequence_rate_handles_rollover_and_dropped_samples() {
        let mut rollover = SequenceStatistics::default();
        rollover.observe(GraphSampleRate::Sps2, 65_300);
        rollover.observe(GraphSampleRate::Sps2, 264);
        assert_eq!(rollover.delivered_sample_rate().unwrap().get::<hertz>(), 2.0);

        let mut dropped = SequenceStatistics::default();
        dropped.observe(GraphSampleRate::Sps50, 100);
        dropped.observe(GraphSampleRate::Sps50, 140);
        assert_eq!(dropped.delivered_sample_rate().unwrap().get::<hertz>(), 25.0);
        assert_eq!(dropped.missing_samples, 1);
    }
}
