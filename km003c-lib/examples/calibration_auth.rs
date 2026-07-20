use std::time::Duration;

use km003c_lib::{Attribute, AttributeSet, DeviceConfig, GraphSampleRate, KM003C};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut device = KM003C::new(DeviceConfig::vendor().skip_reset()).await?;
    let initial_level = device.state().map(|state| state.auth_level).unwrap_or(0);
    println!("Initial authentication level: {initial_level}");

    let result = device.authenticate_calibration().await?;
    println!(
        "Calibration authentication level: {} (attribute 0x{:04x})",
        result.auth_level, result.attribute
    );

    device.start_graph_mode(GraphSampleRate::Sps50).await?;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let response = device.request_data(AttributeSet::single(Attribute::AdcQueue)).await;
    device.stop_graph_mode().await?;

    let response = response?;
    let samples = response.get_adc_queue().map(|queue| queue.samples.len()).unwrap_or(0);
    println!("AdcQueue samples received after level-2 auth: {samples}");

    Ok(())
}
