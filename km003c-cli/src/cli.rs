use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum, error::ErrorKind};
use km003c_lib::{DeviceConfig, DeviceSelector};

use crate::{adc, firmware, logs, memory, pd};

/// Read measurements, download recordings, and inspect a POWER-Z KM003C.
#[derive(Debug, Parser)]
#[command(name = "km003c", version, about)]
pub struct Cli {
    #[command(flatten)]
    pub connection: ConnectionOptions,

    /// Show protocol and USB debug logs on stderr.
    #[arg(short, long, global = true)]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Args)]
pub struct ConnectionOptions {
    /// USB interface; HID is supported only for `adc read`.
    #[arg(long, global = true, value_enum, default_value = "vendor")]
    pub interface: Interface,

    /// Select a meter by its USB serial number.
    #[arg(long, global = true, value_parser = clap::builder::NonEmptyStringValueParser::new())]
    pub serial: Option<String>,

    /// Skip USB reset (the default on macOS).
    #[arg(long, global = true, conflicts_with = "reset")]
    pub no_reset: bool,

    /// Reset USB before connecting (the default outside macOS).
    #[arg(long, global = true)]
    pub reset: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Interface {
    Vendor,
    Hid,
}

impl ConnectionOptions {
    pub fn config(&self) -> DeviceConfig {
        let config = match self.interface {
            Interface::Vendor => DeviceConfig::vendor(),
            Interface::Hid => DeviceConfig::hid(),
        };
        let config = if self.no_reset || (cfg!(target_os = "macos") && !self.reset) {
            config.skip_reset()
        } else {
            config
        };
        match &self.serial {
            Some(serial) => config.select(DeviceSelector::SerialNumber(serial.clone())),
            None => config,
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Inspect, download, and install firmware, including older releases.
    Firmware {
        #[command(subcommand)]
        command: firmware::Command,
    },
    /// Display device, firmware, and authentication information.
    Info,
    /// Read one measurement or stream ADC samples.
    Adc {
        #[command(subcommand)]
        command: adc::Command,
    },
    /// List and download offline recordings stored on the meter.
    Logs {
        #[command(subcommand)]
        command: logs::Command,
    },
    /// Capture USB Power Delivery messages and firmware traces.
    Pd {
        #[command(subcommand)]
        command: pd::Command,
    },
    /// Inspect device memory for protocol research.
    Debug {
        #[command(subcommand)]
        command: DebugCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum DebugCommand {
    /// Read or scan device memory.
    Memory {
        #[command(subcommand)]
        command: memory::Command,
    },
}

impl Cli {
    /// Reject unsupported combinations before opening or resetting USB.
    pub fn validate(&self) -> std::result::Result<(), clap::Error> {
        if matches!(self.command, Command::Firmware { .. }) && self.connection.reset {
            return Err(Self::command().error(
                ErrorKind::ArgumentConflict,
                "firmware commands do not reset USB; omit --reset",
            ));
        }
        if self.connection.interface == Interface::Hid
            && !matches!(
                self.command,
                Command::Adc {
                    command: adc::Command::Read
                }
            )
        {
            return Err(Self::command().error(
                ErrorKind::ArgumentConflict,
                "--interface hid is supported only for `adc read`; use --interface vendor for this command",
            ));
        }
        if let Command::Logs {
            command: logs::Command::Download(args),
        } = &self.command
        {
            args.output_format()
                .map_err(|error| Self::command().error(ErrorKind::ValueValidation, error.to_string()))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_tree_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn all_workflows_are_available_under_one_binary() {
        for arguments in [
            vec!["info"],
            vec!["adc", "read", "--interface", "hid"],
            vec!["adc", "stream", "--rate", "1000", "--duration", "1", "--every", "1"],
            vec!["logs", "list", "--json"],
            vec!["logs", "download", "--latest", "-o", "recording.csv"],
            vec!["logs", "download", "--index", "0", "--format", "json"],
            vec!["pd", "capture", "--duration", "1", "--raw"],
            vec!["pd", "trace", "--polls", "1", "--interval-ms", "10"],
            vec!["debug", "memory", "read", "0x420", "--size", "64"],
            vec!["debug", "memory", "scan", "--full"],
            vec!["firmware", "inspect", "image.mencrypt"],
            vec!["firmware", "check", "image.mencrypt"],
            vec![
                "firmware",
                "update",
                "image.mencrypt",
                "--yes",
                "--backup",
                "backup.bin",
            ],
            vec!["firmware", "list"],
            vec!["firmware", "download", "1.9.7", "-o", "old.mencrypt"],
        ] {
            let cli = Cli::try_parse_from(std::iter::once("km003c").chain(arguments)).unwrap();
            cli.validate().unwrap();
        }
    }

    #[test]
    fn global_options_work_before_and_after_subcommands() {
        for arguments in [
            vec!["--no-reset", "--verbose", "--serial", "123", "logs", "list"],
            vec!["logs", "list", "--no-reset", "--verbose", "--serial", "123"],
        ] {
            let cli = Cli::try_parse_from(std::iter::once("km003c").chain(arguments)).unwrap();
            assert!(cli.connection.no_reset);
            assert!(cli.verbose);
            assert_eq!(cli.connection.serial.as_deref(), Some("123"));
        }
    }

    #[test]
    fn invalid_arguments_fail_without_usb_access() {
        for arguments in [
            vec!["logs", "download"],
            vec!["logs", "download", "--latest", "--index", "0"],
            vec!["adc", "stream", "--rate", "3"],
            vec!["adc", "stream", "--every", "0"],
            vec!["adc", "stream", "--duration", "0"],
            vec!["pd", "trace", "--polls", "0"],
            vec!["debug", "memory", "read", "0xnope"],
            vec!["debug", "memory", "read", "0x420", "--size", "0"],
            vec!["--reset", "--no-reset", "info"],
            vec!["firmware", "update", "image.mencrypt"],
        ] {
            assert!(Cli::try_parse_from(std::iter::once("km003c").chain(arguments)).is_err());
        }
        for arguments in [
            vec!["--interface", "hid", "logs", "list"],
            vec!["--interface", "hid", "pd", "capture"],
            vec!["--reset", "firmware", "check", "image.mencrypt"],
            vec!["logs", "download", "--latest", "-f", "csv", "-o", "recording.json"],
        ] {
            let cli = Cli::try_parse_from(std::iter::once("km003c").chain(arguments)).unwrap();
            assert!(cli.validate().is_err());
        }
    }
}
