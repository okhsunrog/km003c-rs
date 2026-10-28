mod adc;
mod cli;
mod firmware;
mod logs;
mod memory;
mod pd;

use std::process::ExitCode;

use clap::Parser;
use km003c_lib::{KM003C, Packet};

use cli::{Cli, Command, DebugCommand};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

#[tokio::main]
async fn main() -> ExitCode {
    let args = Cli::parse();
    if let Err(error) = args.validate() {
        error.exit();
    }
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(if args.verbose {
            tracing::Level::TRACE
        } else {
            tracing::Level::WARN
        })
        .init();

    match run(args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: Cli) -> Result {
    if let Command::Firmware { command } = args.command {
        return firmware::run(args.connection, command).await;
    }
    let mut device = KM003C::new(args.connection.config()).await?;
    let result = match args.command {
        Command::Info => {
            println!("{}", device.state().ok_or("device information is unavailable")?);
            Ok(())
        }
        Command::Firmware { .. } => unreachable!("firmware uses its own maintenance connection"),
        Command::Adc { command } => match command {
            adc::Command::Read => adc::read(&mut device).await,
            adc::Command::Stream(args) => adc::stream(&mut device, args).await,
        },
        Command::Logs { command } => logs::run(&mut device, command).await,
        Command::Pd { command } => match command {
            pd::Command::Capture(args) => pd::capture(&mut device, args).await,
            pd::Command::Trace(args) => pd::trace(&mut device, args).await,
        },
        Command::Debug { command } => match command {
            DebugCommand::Memory { command } => match command {
                memory::Command::Read(args) => memory::read(&mut device, args).await,
                memory::Command::Scan { full } => memory::scan(&mut device, full).await,
            },
        },
    };
    let disconnect = device.send(Packet::Disconnect).await;
    result?;
    disconnect?;
    Ok(())
}
