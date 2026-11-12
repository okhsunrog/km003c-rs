use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use clap::{Args, Subcommand};
use km003c_lib::packet::{Attribute, AttributeSet};
use km003c_lib::pd::PdEventData;
use km003c_lib::uom::si::electric_current::ampere;
use km003c_lib::uom::si::electric_potential::volt;
use km003c_lib::uom::si::power::watt;
use km003c_lib::uom::si::time::millisecond;
use km003c_lib::usbpd::protocol_layer::message::Payload;
use km003c_lib::usbpd::protocol_layer::message::data::source_capabilities::{
    Augmented, PowerDataObject, SourceCapabilities,
};
use km003c_lib::usbpd::protocol_layer::message::data::{self, Data};
use km003c_lib::usbpd::protocol_layer::message::extended::Extended;
use km003c_lib::{
    CableIdentity, DecodedPdEvent, DecodedPdMessage, GraphSampleRate, KM003C, MeasurementAccumulator,
    MeasurementSample, Packet, PdChunkState, PdChunkStatus, PdDecodeFailure, PdSessionDecoder,
};

use crate::Result;
use crate::adc::SampleRate;
use km003c_lib::uom::si::time::second;
use km003c_lib::{PdTraceProtocolEvent, PdTraceStateEvent};

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Capture and decode USB Power Delivery messages.
    Capture(CaptureArgs),
    /// Read the firmware's internal PD trace queues.
    Trace(TraceArgs),
}

#[derive(Debug, Args)]
pub struct CaptureArgs {
    /// Capture duration in seconds; Ctrl+C stops early.
    #[arg(short, long, default_value_t = 20, value_parser = clap::value_parser!(u64).range(1..))]
    pub duration: u64,
    /// Include raw message bytes.
    #[arg(long)]
    pub raw: bool,
    /// Capture voltage, current and CC measurements alongside PD messages.
    #[arg(long)]
    pub adc: bool,
    /// ADC samples per second (default: 50); requires --adc.
    #[arg(long, value_enum, requires = "adc")]
    pub rate: Option<SampleRate>,
    /// Print every N-th ADC sample; all accepted samples are saved to CSV.
    #[arg(long, requires = "adc", value_parser = clap::value_parser!(u64).range(1..))]
    pub every: Option<u64>,
    /// Save ADC samples to a new CSV file; requires --adc; never overwrites.
    #[arg(long, requires = "adc")]
    pub adc_output: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct TraceArgs {
    /// Number of trace requests.
    #[arg(short, long, default_value_t = 10, value_parser = clap::value_parser!(u64).range(1..))]
    pub polls: u64,
    /// Delay between requests in milliseconds.
    #[arg(short, long, default_value_t = 1000, value_parser = clap::value_parser!(u64).range(1..))]
    pub interval_ms: u64,
}

pub async fn capture(device: &mut KM003C, args: CaptureArgs) -> Result {
    let rate = GraphSampleRate::from(args.rate.unwrap_or(SampleRate::Sps50));
    if args.adc && !device.adcqueue_enabled() {
        return Err("Authentication failed - AdcQueue not enabled".into());
    }
    let mut adc = if args.adc {
        Some(AdcCapture::new(&args, rate)?)
    } else {
        None
    };
    device.enable_pd_monitor().await?;
    if args.adc
        && let Err(error) = device.start_graph_mode(rate).await
    {
        let _ = device.disable_pd_monitor().await;
        return Err(error.into());
    }

    println!("USB PD Negotiation Capture");
    println!("NOW: Disconnect and reconnect your USB-C load!");
    println!(
        "Capturing for {} seconds... (Press Ctrl+C to stop early)\n",
        args.duration
    );

    let start_time = Instant::now();
    let duration = Duration::from_secs(args.duration);
    let mut decoder = PdSessionDecoder::new();

    let interrupted = {
        let collect = async {
            loop {
                if start_time.elapsed() >= duration {
                    break;
                }

                let packet = device.request_data(capture_mask(args.adc)).await?;
                let capture_s = start_time.elapsed().as_secs_f64();
                if let Some(adc) = adc.as_mut() {
                    adc.observe(&packet, capture_s)?;
                }
                if let Some(stream) = KM003C::extract_pd_events(&packet) {
                    if args.adc && !stream.events.is_empty() {
                        println!("[capture +{capture_s:.3}s] PD batch");
                    }
                    for event in &stream.events {
                        if args.raw
                            && let PdEventData::PdMessage { wire_data, .. } = &event.data
                        {
                            print_raw(event.timestamp.get::<millisecond>(), wire_data);
                        }

                        let decoded = decoder.decode_event(event);
                        print_decoded(&decoded, decoder.source_capabilities());
                    }
                }

                tokio::time::sleep(Duration::from_millis(15)).await;
            }
            Ok::<(), Box<dyn std::error::Error>>(())
        };
        tokio::select! {
            result = collect => result,
            signal = tokio::signal::ctrl_c() => signal.map_err(Into::into),
        }
    };

    // Always stop both streams, including after read/write errors and Ctrl+C.
    let graph_stopped = if args.adc {
        device.stop_graph_mode().await
    } else {
        Ok(())
    };
    let stopped = device.disable_pd_monitor().await;
    let saved = adc.as_mut().map(AdcCapture::finish).transpose();
    interrupted?;
    saved?;
    graph_stopped?;
    stopped?;
    println!("\nCapture complete.");
    Ok(())
}

fn capture_mask(adc: bool) -> AttributeSet {
    let mask = AttributeSet::single(Attribute::PdPacket);
    if adc { mask.with(Attribute::AdcQueue) } else { mask }
}

struct AdcCapture {
    rate: GraphSampleRate,
    every: u64,
    csv: Option<BufWriter<File>>,
    measurements: MeasurementAccumulator,
    samples: u64,
    missing: u64,
    discarded: u64,
    voltage_min: f64,
    voltage_max: f64,
}

impl AdcCapture {
    fn new(args: &CaptureArgs, rate: GraphSampleRate) -> Result<Self> {
        let mut csv = args
            .adc_output
            .as_ref()
            .map(|path| File::create_new(path).map(BufWriter::new))
            .transpose()?;
        if let Some(csv) = &mut csv {
            writeln!(
                csv,
                "capture_s,elapsed_us,sequence,vbus_uv,ibus_ua,power_uw,cc1_uv,cc2_uv,dp_uv,dm_uv,missing_samples"
            )?;
        }
        Ok(Self {
            rate,
            every: args.every.unwrap_or(match rate {
                GraphSampleRate::Sps2 | GraphSampleRate::Sps10 => 1,
                GraphSampleRate::Sps50 => 5,
                GraphSampleRate::Sps1000 => 100,
            }),
            csv,
            measurements: MeasurementAccumulator::default(),
            samples: 0,
            missing: 0,
            discarded: 0,
            voltage_min: f64::INFINITY,
            voltage_max: f64::NEG_INFINITY,
        })
    }

    fn observe(&mut self, packet: &Packet, capture_s: f64) -> Result {
        if let Some(queue) = packet.get_adc_queue() {
            for sample in &queue.samples {
                let Some(sample) = self.measurements.push(*sample, self.rate) else {
                    self.discarded += 1;
                    continue;
                };
                self.samples += 1;
                self.missing += u64::from(sample.missing_samples);
                let voltage = sample.vbus_uv as f64 / 1e6;
                self.voltage_min = self.voltage_min.min(voltage);
                self.voltage_max = self.voltage_max.max(voltage);
                if let Some(csv) = &mut self.csv {
                    write_adc_row(csv, capture_s, sample)?;
                }
                if (self.samples - 1).is_multiple_of(self.every) {
                    println!(
                        "[capture +{capture_s:.3}s] ADC +{:.3}s seq={} VBUS={voltage:.3}V IBUS={:.3}A CC1={:.3}V CC2={:.3}V missing={}",
                        sample.elapsed_seconds(),
                        sample.sequence,
                        sample.ibus_ua as f64 / 1e6,
                        sample.cc1_uv as f64 / 1e6,
                        sample.cc2_uv as f64 / 1e6,
                        sample.missing_samples,
                    );
                }
            }
        }
        if let Some(csv) = &mut self.csv {
            csv.flush()?;
        }
        Ok(())
    }

    fn finish(&mut self) -> Result {
        if let Some(csv) = &mut self.csv {
            csv.flush()?;
        }
        println!(
            "ADC: {} samples, {} missing, {} discarded",
            self.samples, self.missing, self.discarded
        );
        if self.samples > 0 {
            println!("VBUS range: {:.3}..{:.3} V", self.voltage_min, self.voltage_max);
        }
        Ok(())
    }
}

fn write_adc_row(output: &mut impl Write, capture_s: f64, sample: MeasurementSample) -> std::io::Result<()> {
    writeln!(
        output,
        "{capture_s:.6},{},{},{},{},{},{},{},{},{},{}",
        sample.elapsed_us,
        sample.sequence,
        sample.vbus_uv,
        sample.ibus_ua,
        sample.power_uw,
        sample.cc1_uv,
        sample.cc2_uv,
        sample.dp_uv,
        sample.dm_uv,
        sample.missing_samples
    )
}

fn print_raw(timestamp_ms: f64, wire_data: &[u8]) {
    print!("[{:>8.3}s] RAW[{}]: ", timestamp_ms / 1000.0, wire_data.len());
    for (index, byte) in wire_data.iter().enumerate() {
        if index > 0 && index % 16 == 0 {
            print!("\n                     ");
        }
        print!("{byte:02X} ");
    }
    println!();
}

fn print_decoded(decoded: &DecodedPdEvent, source_caps: Option<&SourceCapabilities>) {
    match decoded {
        DecodedPdEvent::Connect { timestamp } => {
            println!("[{:>8.3}s] ** CONNECT **", timestamp.get::<millisecond>() / 1000.0);
        }
        DecodedPdEvent::Disconnect { timestamp } => {
            println!("[{:>8.3}s] ** DISCONNECT **", timestamp.get::<millisecond>() / 1000.0);
        }
        DecodedPdEvent::DeviceStatus { timestamp, code, raw } => {
            println!(
                "[{:>8.3}s] Device status 0x{code:02X}: {raw:02X?}",
                timestamp.get::<millisecond>() / 1000.0
            );
        }
        DecodedPdEvent::Message(message) => print_message(message, source_caps),
        DecodedPdEvent::Chunk(status) => print_chunk_status(*status),
        DecodedPdEvent::Error(failure) => print_failure(failure),
    }
}

fn print_message(decoded: &DecodedPdMessage, source_caps: Option<&SourceCapabilities>) {
    let message = &decoded.message;
    println!(
        "[{:>8.3}s] SOP{}: {:<20} (ID={}, ROLE={:?}/{:?})",
        decoded.timestamp.get::<millisecond>() / 1000.0,
        decoded.sop,
        format!("{:?}", message.header.message_type()),
        message.header.message_id(),
        message.header.port_power_role(),
        message.header.port_data_role(),
    );

    match &message.payload {
        Some(Payload::Data(Data::SourceCapabilities(capabilities))) => {
            print_capabilities(capabilities.pdos(), "SPR Source Capabilities");
        }
        Some(Payload::Data(Data::Request(request))) => print_request(request, source_caps),
        Some(Payload::Data(Data::EprMode(mode))) => println!("             EPR Mode: {mode:?}"),
        Some(Payload::Data(Data::VendorDefined((header, objects)))) => {
            let mut words = vec![u32::from(*header)];
            words.extend_from_slice(objects);
            match CableIdentity::from_vdm_words(decoded.sop, &words) {
                Some(identity) => {
                    for line in identity.describe() {
                        println!("             {line}");
                    }
                }
                None => println!(
                    "             VDM: {}",
                    words
                        .iter()
                        .map(|word| format!("0x{word:08X}"))
                        .collect::<Vec<_>>()
                        .join(" ")
                ),
            }
        }
        Some(Payload::Data(Data::Unknown)) => println!("             Unknown Data Message"),
        Some(Payload::Data(data)) => println!("             Data: {data:?}"),
        Some(Payload::Extended(Extended::EprSourceCapabilities(pdos))) => {
            print_capabilities(pdos.as_slice(), "EPR Source Capabilities");
        }
        Some(Payload::Extended(Extended::ExtendedControl(control))) => println!(
            "             Extended Control: {:?} (data=0x{:02X})",
            control.message_type(),
            control.data()
        ),
        Some(Payload::Extended(extended)) => println!("             Extended: {extended:?}"),
        None => {}
    }
}

fn print_chunk_status(status: PdChunkStatus) {
    let timestamp = status.timestamp.get::<millisecond>() / 1000.0;
    match status.state {
        PdChunkState::Request { chunk_number } => println!(
            "[{timestamp:>8.3}s] SOP{}: Chunk Request (chunk={chunk_number}, type={:?})",
            status.sop, status.message_type
        ),
        PdChunkState::Pending {
            received_chunk,
            next_chunk,
        } => println!(
            "[{timestamp:>8.3}s] SOP{}: {:?} chunk {received_chunk} received, waiting for chunk {next_chunk}",
            status.sop, status.message_type
        ),
        PdChunkState::Requested { chunk_number } => println!(
            "[{timestamp:>8.3}s] SOP{}: {:?} chunk {chunk_number} requested",
            status.sop, status.message_type
        ),
        PdChunkState::Unsupported {
            chunk_number,
            data_size,
        } => println!(
            "[{timestamp:>8.3}s] SOP{}: Chunked {:?} (chunk {chunk_number}, {data_size} bytes) - not assembled",
            status.sop, status.message_type
        ),
    }
}

fn print_failure(failure: &PdDecodeFailure) {
    println!(
        "[{:>8.3}s] SOP{}: Failed to parse: {} (Hex: {:02X?})",
        failure.timestamp.get::<millisecond>() / 1000.0,
        failure.sop,
        failure.error,
        failure.wire_data
    );
}

fn print_request(request: &data::request::PowerSource, source_caps: Option<&SourceCapabilities>) {
    use data::request::PowerSource;

    match request {
        PowerSource::FixedVariableSupply(request) => {
            let current = request.operating_current().get::<ampere>();
            let max_current = request.max_operating_current().get::<ampere>();
            let position = request.object_position();
            if let Some(pdo) = source_caps.and_then(|caps| caps.pdos().get(position as usize - 1)) {
                println!("             RDO: PDO#{position} ({}) @ {current:.1}A", format_pdo(pdo));
            } else {
                println!("             RDO: PDO#{position} @ {current:.1}A (Max {max_current:.1}A)");
            }
        }
        PowerSource::Battery(request) => println!(
            "             RDO: Requesting Battery PDO#{} @ {:.2}W",
            request.object_position(),
            request.operating_power().get::<watt>()
        ),
        PowerSource::Pps(request) => println!(
            "             RDO: Requesting PPS PDO#{} @ {:.2}V / {:.2}A",
            request.object_position(),
            request.output_voltage().get::<volt>(),
            request.operating_current().get::<ampere>()
        ),
        PowerSource::Avs(request) => println!(
            "             RDO: Requesting AVS PDO#{} @ {:.2}V / {:.2}A",
            request.object_position(),
            request.output_voltage().get::<volt>(),
            request.operating_current().get::<ampere>()
        ),
        PowerSource::EprRequest(request) => print_epr_request(request.rdo, &request.pdo),
        PowerSource::Unknown(raw) => {
            let position = raw.object_position();
            if let Some(pdo) = source_caps.and_then(|caps| caps.pdos().get(position as usize - 1)) {
                let request = data::request::FixedVariableSupply(raw.0);
                println!(
                    "             RDO: Requesting PDO#{position} ({}) @ {:.1}A",
                    format_pdo(pdo),
                    request.operating_current().get::<ampere>()
                );
            } else {
                println!("             RDO: Requesting PDO#{position} (Raw=0x{:08X})", raw.0);
            }
        }
    }
}

fn print_epr_request(rdo: u32, pdo: &PowerDataObject) {
    use data::request::{Avs as RdoAvs, FixedVariableSupply as RdoFixed, RawDataObject};

    let position = RawDataObject(rdo).object_position();
    match pdo {
        PowerDataObject::FixedSupply(fixed) => {
            let request = RdoFixed(rdo);
            println!(
                "             RDO: EPR Fixed PDO#{position} ({:.1}V) @ {:.2}A (Max {:.2}A)",
                fixed.voltage().get::<volt>(),
                request.operating_current().get::<ampere>(),
                request.max_operating_current().get::<ampere>()
            );
        }
        PowerDataObject::Augmented(Augmented::Spr(pps)) => {
            let request = RdoAvs(rdo);
            println!(
                "             RDO: EPR PPS PDO#{position} ({:.1}-{:.1}V) @ {:.2}V / {:.2}A",
                pps.min_voltage().get::<volt>(),
                pps.max_voltage().get::<volt>(),
                request.output_voltage().get::<volt>(),
                request.operating_current().get::<ampere>()
            );
        }
        PowerDataObject::Augmented(Augmented::Epr(avs)) => {
            let request = RdoAvs(rdo);
            println!(
                "             RDO: EPR AVS PDO#{position} ({:.1}-{:.1}V @ {:.0}W) @ {:.2}V / {:.2}A",
                avs.min_voltage().get::<volt>(),
                avs.max_voltage().get::<volt>(),
                avs.pd_power().get::<watt>(),
                request.output_voltage().get::<volt>(),
                request.operating_current().get::<ampere>()
            );
        }
        PowerDataObject::Augmented(_) => {
            println!("             RDO: EPR Augmented PDO#{position} (Raw=0x{rdo:08X})");
        }
        _ => println!("             RDO: EPR PDO#{position} (Raw=0x{rdo:08X}, PDO={pdo:?})"),
    }
}

fn format_pdo(pdo: &PowerDataObject) -> String {
    match pdo {
        PowerDataObject::FixedSupply(fixed) => {
            let voltage = fixed.voltage().get::<volt>();
            let current = fixed.max_current().get::<ampere>();
            let mut flags = Vec::new();
            if fixed.dual_role_power() {
                flags.push("DRP");
            }
            if fixed.usb_communications_capable() {
                flags.push("USB");
            }
            if fixed.dual_role_data() {
                flags.push("DRD");
            }
            if fixed.unconstrained_power() {
                flags.push("UP");
            }
            if fixed.epr_mode_capable() {
                flags.push("EPR");
            }
            let flags = if flags.is_empty() {
                String::new()
            } else {
                format!(" [{}]", flags.join(","))
            };
            format!("Fixed {voltage:.0}V @ {current:.1}A ({:.0}W){flags}", voltage * current)
        }
        PowerDataObject::Battery(battery) => format!(
            "Battery {:.0}-{:.0}V @ {:.0}W",
            battery.min_voltage().get::<volt>(),
            battery.max_voltage().get::<volt>(),
            battery.max_power().get::<watt>()
        ),
        PowerDataObject::VariableSupply(variable) => format!(
            "Variable {:.0}-{:.0}V @ {:.1}A",
            variable.min_voltage().get::<volt>(),
            variable.max_voltage().get::<volt>(),
            variable.max_current().get::<ampere>()
        ),
        PowerDataObject::Augmented(Augmented::Spr(pps)) => {
            let min_voltage = pps.min_voltage().get::<volt>();
            let max_voltage = pps.max_voltage().get::<volt>();
            let current = pps.max_current().get::<ampere>();
            let limited = if pps.pps_power_limited() { " (limited)" } else { "" };
            format!(
                "PPS {min_voltage:.1}-{max_voltage:.1}V @ {current:.1}A ({:.0}W){limited}",
                max_voltage * current
            )
        }
        PowerDataObject::Augmented(Augmented::Epr(avs)) => format!(
            "EPR AVS {:.0}-{:.0}V @ {:.0}W",
            avs.min_voltage().get::<volt>(),
            avs.max_voltage().get::<volt>(),
            avs.pd_power().get::<watt>()
        ),
        PowerDataObject::Augmented(Augmented::Unknown(raw)) => format!("Augmented(0x{raw:08X})"),
        PowerDataObject::Unknown(raw) => format!("Unknown(0x{:08X})", raw.0),
    }
}

fn print_capabilities(capabilities: &[PowerDataObject], title: &str) {
    println!("             [{title}]");
    for (index, pdo) in capabilities.iter().enumerate() {
        if matches!(pdo, PowerDataObject::FixedSupply(fixed) if fixed.0 == 0) {
            println!("             PDO[{}]: --- (separator) ---", index + 1);
        } else {
            println!("             PDO[{}]: {}", index + 1, format_pdo(pdo));
        }
    }
}

pub async fn trace(device: &mut KM003C, args: TraceArgs) -> Result {
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
            "  protocol {:?} (0x{:02x}) uptime={:.0}s",
            event.kind,
            u8::from(event.kind),
            event.timestamp.get::<second>()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use km003c_lib::uom::si::f64::{ElectricCurrent, ElectricPotential};
    use km003c_lib::{AdcQueueData, AdcQueueSample, PayloadData};

    #[test]
    fn combined_capture_keeps_pd_and_adc_and_accounts_for_gaps() {
        let args = CaptureArgs {
            duration: 1,
            raw: false,
            adc: true,
            rate: None,
            every: Some(100),
            adc_output: None,
        };
        let mut capture = AdcCapture::new(&args, GraphSampleRate::Sps50).unwrap();
        let sample = |sequence| {
            let vbus = ElectricPotential::new::<volt>(5.125);
            let ibus = ElectricCurrent::new::<ampere>(-0.015);
            AdcQueueSample {
                sequence,
                marker: 0,
                vbus,
                ibus,
                power: vbus * ibus,
                cc1: ElectricPotential::new::<volt>(0.8),
                cc2: ElectricPotential::new::<volt>(0.0),
                vdp: ElectricPotential::new::<volt>(0.0),
                vdm: ElectricPotential::new::<volt>(0.0),
            }
        };
        let packet = Packet::DataResponse {
            payloads: vec![PayloadData::AdcQueue(AdcQueueData {
                rate: GraphSampleRate::Sps50,
                samples: vec![sample(65520), sample(4), sample(44), sample(44)],
            })],
        };
        capture.observe(&packet, 1.5).unwrap();
        assert_eq!((capture.samples, capture.missing, capture.discarded), (3, 1, 1));
        assert_eq!(capture.voltage_min, 5.125);
        assert!(capture_mask(true).contains_all([Attribute::PdPacket, Attribute::AdcQueue]));
        assert!(!capture_mask(false).contains(Attribute::AdcQueue));

        let mut accumulator = MeasurementAccumulator::default();
        let measured = accumulator.push(sample(1), GraphSampleRate::Sps50).unwrap();
        let mut row = Vec::new();
        write_adc_row(&mut row, 1.5, measured).unwrap();
        assert_eq!(
            String::from_utf8(row).unwrap(),
            "1.500000,0,1,5125000,-15000,-76875,800000,0,0,0,0\n"
        );
    }

    #[test]
    fn adc_output_preserves_an_existing_file() {
        let path = std::env::current_exe().unwrap();
        let args = CaptureArgs {
            duration: 1,
            raw: false,
            adc: true,
            rate: None,
            every: None,
            adc_output: Some(path),
        };
        assert!(AdcCapture::new(&args, GraphSampleRate::Sps50).is_err());
    }
}
