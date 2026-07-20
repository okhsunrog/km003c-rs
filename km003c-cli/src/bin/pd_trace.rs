use std::error::Error;
use std::time::Duration;

use clap::Parser;
use km003c_lib::uom::si::time::second;
use km003c_lib::{DeviceConfig, KM003C, PdTraceProtocolEvent, PdTraceStateEvent};

/// Drain and display the KM003C firmware's internal USB PD trace queues.
#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Args {
    /// Number of trace requests to make.
    #[arg(short, long, default_value_t = 10)]
    polls: usize,

    /// Delay between trace requests.
    #[arg(short, long, default_value_t = 1000)]
    interval_ms: u64,

    /// Show raw USB traffic.
    #[arg(short, long)]
    verbose: bool,

    /// Skip USB reset.
    #[arg(long, default_value_t = cfg!(target_os = "macos"))]
    no_reset: bool,

    /// Force USB reset even when --no-reset is the platform default.
    #[arg(long)]
    reset: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .with_max_level(if args.verbose {
            tracing::Level::TRACE
        } else {
            tracing::Level::WARN
        })
        .init();

    let mut config = DeviceConfig::vendor();
    if args.no_reset && !args.reset {
        config = config.skip_reset();
    }
    let mut device = KM003C::new(config).await?;

    for poll in 0..args.polls {
        let trace = device.request_pd_trace().await?;
        println!(
            "poll {}: {} state events, {} protocol events",
            poll + 1,
            trace.state_events.len(),
            trace.protocol_events.len()
        );
        print_state_events(&trace.state_events);
        print_protocol_events(&trace.protocol_events);

        if poll + 1 < args.polls {
            tokio::time::sleep(Duration::from_millis(args.interval_ms)).await;
        }
    }

    Ok(())
}

fn print_state_events(events: &[PdTraceStateEvent]) {
    for event in events {
        println!(
            "  state    {:?} (0x{:02x}) uptime={:.0}s",
            event.state,
            u8::from(event.state),
            event.timestamp.get::<second>()
        );
    }
}

fn print_protocol_events(events: &[PdTraceProtocolEvent]) {
    for event in events {
        println!(
            "  protocol code=0x{:02x} uptime={:.0}s",
            event.code,
            event.timestamp.get::<second>()
        );
    }
}
