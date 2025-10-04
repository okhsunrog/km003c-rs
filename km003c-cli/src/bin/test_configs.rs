use km003c_lib::device::{DeviceConfig, TransferType, INTERFACE_VENDOR, ENDPOINT_OUT_VENDOR, ENDPOINT_IN_VENDOR};
use km003c_lib::KM003C;
use std::error::Error;
use std::time::Instant;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    println!("{}", "=".repeat(70));
    println!("KM003C Device Configuration Test");
    println!("{}", "=".repeat(70));
    println!();

    // Test configurations to try
    let configs = vec![
        (
            "HID Interface (default)",
            DeviceConfig::default(),
        ),
        (
            "Vendor Interface with reset",
            DeviceConfig::vendor_interface(),
        ),
        (
            "Vendor Interface without reset",
            DeviceConfig {
                interface: INTERFACE_VENDOR,
                endpoint_out: ENDPOINT_OUT_VENDOR,
                endpoint_in: ENDPOINT_IN_VENDOR,
                transfer_type: TransferType::Bulk,
                auto_detach: true,
                reset_before_claim: false,
            },
        ),
    ];

    for (name, config) in configs {
        println!("{}", "─".repeat(70));
        println!("Testing: {}", name);
        println!("  Interface: {}, Type: {:?}", config.interface, config.transfer_type);
        println!("  Endpoints: OUT=0x{:02X}, IN=0x{:02X}", config.endpoint_out, config.endpoint_in);
        println!("  Reset before claim: {}", config.reset_before_claim);
        println!();

        let start = Instant::now();
        
        match test_config(config).await {
            Ok(stats) => {
                let elapsed = start.elapsed();
                println!("  ✅ SUCCESS!");
                println!("  Time: {:?}", elapsed);
                println!("  ADC: VBUS={:.3}V, IBUS={:.3}A, Temp={:.1}°C", 
                         stats.vbus, stats.ibus, stats.temp);
                println!("  Latency: {:?}", stats.latency);
            }
            Err(e) => {
                println!("  ❌ FAILED: {}", e);
            }
        }
        println!();
        
        // Wait a bit between tests
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }

    println!("{}", "=".repeat(70));
    println!("✅ Testing complete!");
    println!("{}", "=".repeat(70));

    Ok(())
}

struct TestStats {
    vbus: f64,
    ibus: f64,
    temp: f64,
    latency: std::time::Duration,
}

async fn test_config(config: DeviceConfig) -> Result<TestStats, Box<dyn Error>> {
    // Connect
    let mut device = KM003C::with_config(config).await?;
    
    // Request ADC data and measure latency
    let start = Instant::now();
    let adc_data = device.request_adc_data().await?;
    let latency = start.elapsed();
    
    Ok(TestStats {
        vbus: adc_data.vbus_v,
        ibus: adc_data.ibus_a,
        temp: adc_data.temp_c,
        latency,
    })
}
