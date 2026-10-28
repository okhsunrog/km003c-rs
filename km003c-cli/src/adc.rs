use crate::Result;
use clap::{Args, Subcommand, ValueEnum};
use km003c_lib::uom::si::electric_current::ampere;
use km003c_lib::uom::si::electric_potential::volt;
use km003c_lib::uom::si::f64::Frequency;
use km003c_lib::uom::si::frequency::hertz;
use km003c_lib::uom::si::power::watt;
use km003c_lib::uom::si::thermodynamic_temperature::degree_celsius;
use km003c_lib::{
    GraphSampleRate, KM003C,
    packet::{Attribute, AttributeSet},
};
use std::time::Duration;

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Read one set of ADC measurements.
    Read,
    /// Stream ADC measurements at a fixed sample rate.
    Stream(StreamArgs),
}

#[derive(Debug, Args)]
pub struct StreamArgs {
    /// Sample rate in samples per second.
    #[arg(short, long, value_enum, default_value = "50")]
    pub rate: SampleRate,
    /// Capture duration in seconds.
    #[arg(short, long, default_value_t = 10, value_parser = clap::value_parser!(u64).range(1..))]
    pub duration: u64,
    /// Print every N-th sample; defaults depend on the sample rate.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    pub every: Option<u64>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum SampleRate {
    #[value(name = "2")]
    Sps2,
    #[value(name = "10")]
    Sps10,
    #[value(name = "50")]
    Sps50,
    #[value(name = "1000")]
    Sps1000,
}

impl From<SampleRate> for GraphSampleRate {
    fn from(rate: SampleRate) -> Self {
        match rate {
            SampleRate::Sps2 => Self::Sps2,
            SampleRate::Sps10 => Self::Sps10,
            SampleRate::Sps50 => Self::Sps50,
            SampleRate::Sps1000 => Self::Sps1000,
        }
    }
}

pub async fn read(device: &mut KM003C) -> Result {
    // Request ADC data
    println!("📊 Requesting ADC data...");
    let adc_data = device.request_adc_data().await?;

    // Display the ADC data with nice formatting
    println!("\n{}", "=".repeat(50));
    println!("📈 ADC Measurements");
    println!("{}", "=".repeat(50));

    // Main measurements
    println!("\n⚡ Power Measurements:");
    println!("  VBUS:        {:>8.3} V", adc_data.vbus.get::<volt>());
    println!("  IBUS:        {:>8.3} A", adc_data.ibus.get::<ampere>());
    println!("  IBUS (abs):  {:>8.3} A", adc_data.current_abs().get::<ampere>());
    println!("  Power:       {:>8.3} W", adc_data.power.get::<watt>());
    println!("  Power (abs): {:>8.3} W", adc_data.power_abs().get::<watt>());

    // Averaged measurements
    println!("\n📊 Averaged:");
    println!("  VBUS avg:    {:>8.3} V", adc_data.vbus_average.get::<volt>());
    println!("  IBUS avg:    {:>8.3} A", adc_data.ibus_average.get::<ampere>());

    // Temperature
    println!("\n🌡️  Temperature:");
    println!(
        "  Device:      {:>8.1} °C",
        adc_data.temperature.get::<degree_celsius>()
    );

    // USB data lines
    println!("\n🔌 USB Data Lines:");
    println!("  D+:          {:>8.3} V", adc_data.vdp.get::<volt>());
    println!("  D-:          {:>8.3} V", adc_data.vdm.get::<volt>());
    println!("  D+ avg:      {:>8.3} V", adc_data.vdp_average.get::<volt>());
    println!("  D- avg:      {:>8.3} V", adc_data.vdm_average.get::<volt>());

    // USB-C CC lines
    println!("\n🔗 USB-C CC Lines:");
    println!("  CC1:         {:>8.3} V", adc_data.cc1.get::<volt>());
    println!("  CC2:         {:>8.3} V", adc_data.cc2.get::<volt>());
    println!("  CC2 avg:     {:>8.3} V", adc_data.cc2_average.get::<volt>());

    // Sample rate and internal voltage
    println!("\n⚙️  Device Info:");
    match adc_data.sample_rate {
        Some(rate) => println!("  Sample Rate: {rate}"),
        None => println!("  Sample Rate: Unknown ({})", adc_data.sample_rate_raw),
    }
    println!("  Internal VDD: {:>7.3} V", adc_data.internal_vdd.get::<volt>());

    println!("\n{}", "=".repeat(50));

    Ok(())
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

pub async fn stream(device: &mut KM003C, args: StreamArgs) -> Result {
    let rate = GraphSampleRate::from(args.rate);
    let print_interval = args.every.unwrap_or(match rate {
        GraphSampleRate::Sps2 | GraphSampleRate::Sps10 => 1,
        GraphSampleRate::Sps50 => 5,
        GraphSampleRate::Sps1000 => 50,
    });
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
        rate.frequency().get::<hertz>(),
        rate as u16
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

    let interrupted = {
        let collect = async {
            while start_time.elapsed() < Duration::from_secs(args.duration) {
                // Request AdcQueue data using library API
                let mask = AttributeSet::single(Attribute::AdcQueue);
                let packet = match device.request_data(mask).await {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::debug!("Request error: {e}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };

                // Extract AdcQueue data from the parsed packet
                let queue_data = match packet.get_adc_queue() {
                    Some(data) => data,
                    None => {
                        tracing::debug!("No AdcQueue data in response");
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        continue;
                    }
                };

                if queue_data.samples.is_empty() {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    continue;
                }

                packet_count += 1;

                if let Some((first, last)) = queue_data.sequence_range() {
                    tracing::debug!(
                        "Packet {} - {} samples, seq {}..{}",
                        packet_count,
                        queue_data.samples.len(),
                        first,
                        last
                    );
                }

                for sample in &queue_data.samples {
                    let previous = sequence_statistics.previous;
                    let dropped = sequence_statistics.observe(rate, sample.sequence);
                    if dropped > 0 {
                        let gap = sample
                            .sequence
                            .wrapping_sub(previous.expect("a gap requires a previous sample"));
                        tracing::warn!("{dropped} samples dropped (gap={gap})");
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
        };
        tokio::select! {
            () = collect => Ok(()),
            signal = tokio::signal::ctrl_c() => signal,
        }
    };

    println!("{}", "=".repeat(90));
    println!("\nStopping streaming...");

    // Stop graph mode using library API
    let stopped = device.stop_graph_mode().await;
    interrupted?;
    stopped?;
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
    println!("  Expected rate: {} SPS", rate.frequency().get::<hertz>());

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
