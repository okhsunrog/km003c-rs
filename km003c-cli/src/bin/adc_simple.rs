use clap::Parser;
use km003c_lib::{DeviceConfig, KM003C};
use std::error::Error;

/// Simple ADC data reader for POWER-Z KM003C
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// USB interface to use: "vendor" (Interface 0, Bulk) or "hid" (Interface 3, Interrupt)
    #[arg(short, long, default_value = "vendor", value_parser = ["vendor", "hid"])]
    interface: String,

    /// Verbose logging (show USB traffic)
    #[arg(short, long)]
    verbose: bool,

    /// Skip USB reset (defaults to true on macOS for compatibility)
    #[arg(long, default_value_t = cfg!(target_os = "macos"))]
    no_reset: bool,

    /// Force USB reset even on macOS (overrides --no-reset)
    #[arg(long)]
    reset: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    // Initialize logging based on verbosity flag
    let log_level = if args.verbose {
        tracing::Level::TRACE
    } else {
        tracing::Level::INFO
    };

    tracing_subscriber::fmt().with_max_level(log_level).init();

    // Select configuration based on CLI argument
    let mut config = match args.interface.as_str() {
        "vendor" => DeviceConfig::vendor(),
        "hid" => DeviceConfig::hid(),
        _ => unreachable!(), // clap validates this
    };

    if args.no_reset && !args.reset {
        config = config.skip_reset();
    }

    println!(
        "Searching for POWER-Z KM003C ({} interface)...\n",
        args.interface.to_uppercase()
    );

    // Connect to device - mode is determined by config:
    // - Vendor: Full mode with device info
    // - HID: Basic mode (ADC/PD only)
    let mut device = KM003C::new(config).await?;

    if let Some(state) = device.state() {
        // Full mode - show device info using Display impl
        println!("{}\n", state);
    } else {
        // Basic mode - HID interface
        println!("Connected (Basic mode - ADC/PD polling)\n");
    }

    // Request ADC data
    println!("📊 Requesting ADC data...");
    let adc_data = device.request_adc_data().await?;

    // Display the ADC data with nice formatting
    println!("\n{}", "=".repeat(50));
    println!("📈 ADC Measurements");
    println!("{}", "=".repeat(50));

    // Main measurements
    println!("\n⚡ Power Measurements:");
    println!("  VBUS:        {:>8.3} V", adc_data.vbus_v);
    println!("  IBUS:        {:>8.3} A", adc_data.ibus_a);
    println!("  IBUS (abs):  {:>8.3} A", adc_data.current_abs_a());
    println!("  Power:       {:>8.3} W", adc_data.power_w);
    println!("  Power (abs): {:>8.3} W", adc_data.power_abs_w());

    // Averaged measurements
    println!("\n📊 Averaged:");
    println!("  VBUS avg:    {:>8.3} V", adc_data.vbus_avg_v);
    println!("  IBUS avg:    {:>8.3} A", adc_data.ibus_avg_a);

    // Temperature
    println!("\n🌡️  Temperature:");
    println!("  Device:      {:>8.1} °C", adc_data.temp_c);

    // USB data lines
    println!("\n🔌 USB Data Lines:");
    println!("  D+:          {:>8.3} V", adc_data.vdp_v);
    println!("  D-:          {:>8.3} V", adc_data.vdm_v);
    println!("  D+ avg:      {:>8.3} V", adc_data.vdp_avg_v);
    println!("  D- avg:      {:>8.3} V", adc_data.vdm_avg_v);

    // USB-C CC lines
    println!("\n🔗 USB-C CC Lines:");
    println!("  CC1:         {:>8.3} V", adc_data.cc1_v);
    println!("  CC2:         {:>8.3} V", adc_data.cc2_v);
    println!("  CC2 avg:     {:>8.3} V", adc_data.cc2_avg_v);

    // Sample rate and internal voltage
    println!("\n⚙️  Device Info:");
    println!("  Sample Rate: {}", adc_data.sample_rate);
    println!("  Internal VDD: {:>7.3} V", adc_data.internal_vdd_v);

    println!("\n{}", "=".repeat(50));
    println!("✅ Done!");

    Ok(())
}
