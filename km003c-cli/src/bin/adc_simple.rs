use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Initialize logging with trace level to see USB traffic
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    // Connect to the device using HID interface (more compatible, like Python example)
    println!("🔍 Searching for POWER-Z KM003C...");
    let mut device = km003c_lib::KM003C::new().await?;  // Uses HID by default
    println!("✅ Connected to POWER-Z KM003C\n");

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
