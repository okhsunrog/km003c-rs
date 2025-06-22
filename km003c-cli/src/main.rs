use km003c_lib::KM003C;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Connect to the device
    let mut device = KM003C::new().await?;
    println!("Connected to POWER-Z KM003C");

    // Request ADC data
    println!("Requesting ADC data...");
    let adc_data = device.request_adc_data().await?;

    // Display the ADC data
    println!("ADC Data:");
    println!("  Voltage: {:.3} V", adc_data.vbus_v);
    println!(
        "  Current: {:.3} A (absolute: {:.3} A)",
        adc_data.ibus_a,
        adc_data.current_abs_a()
    );
    println!(
        "  Power: {:.3} W (absolute: {:.3} W)",
        adc_data.power_w,
        adc_data.power_abs_w()
    );
    println!("  Temperature: {:.1} °C", adc_data.temp_c);
    println!("  Sample Rate: {}", adc_data.sample_rate);

    // Display USB data lines
    println!("USB Data Lines:");
    println!("  D+: {:.3} V", adc_data.vdp_v);
    println!("  D-: {:.3} V", adc_data.vdm_v);

    // Display USB CC lines
    println!("USB CC Lines:");
    println!("  CC1: {:.3} V", adc_data.cc1_v);
    println!("  CC2: {:.3} V", adc_data.cc2_v);

    Ok(())
}
