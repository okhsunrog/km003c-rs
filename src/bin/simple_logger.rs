// src/bin/simple_logger.rs

use anyhow::Result;
use clap::Parser;
use std::time::Duration;
use tokio::{signal, time::sleep};
use tracing::{error, info};
use tracing_subscriber;

use km003c_rs::device::KM003C;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(short, long)]
    continuous: bool,
    #[arg(short, long, default_value_t = 10)]
    samples: u32,
    #[arg(short, long, default_value_t = 200)]
    interval_ms: u64,
    /// Skip the authentication sequence during initialization.
    #[arg(long)]
    no_auth: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    tracing_subscriber::fmt().with_target(false).init();

    tokio::select! {
        res = run(cli) => {
            if let Err(e) = res {
                error!("Application failed: {}", e);
                std::process::exit(1);
            }
        }
        _ = signal::ctrl_c() => {
            info!("Ctrl+C received, shutting down gracefully.");
        }
    }
    Ok(())
}

async fn run(cli: Cli) -> Result<()> {
    // The logic is now much cleaner.
    // We pass !cli.no_auth to the `new` function to control the auth sequence.
    let mut device = KM003C::new(!cli.no_auth).await?;

    info!("--- Entering Data Polling Loop ---");
    let iterations = if cli.continuous { u32::MAX } else { cli.samples };

    for i in 0..iterations {
        match device.poll_sensor_data().await {
            Ok(packet) => {
                info!("[Sample {}] Parsed Sensor Data:\n{}", i + 1, packet);
            }
            Err(e) => {
                error!("Failed to poll sensor data: {}", e);
                break;
            }
        }
        sleep(Duration::from_millis(cli.interval_ms)).await;
    }

    info!("Finished polling.");
    Ok(())
}
