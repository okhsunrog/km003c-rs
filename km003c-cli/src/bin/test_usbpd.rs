use km003c_lib::{
    device::DeviceConfig,
    pd::PdEventData,
    KM003C,
};
use std::time::{Duration, Instant};
use usbpd::protocol_layer::message::data::source_capabilities::SourceCapabilities;
use usbpd::protocol_layer::message::data::{self, Data};
use usbpd::protocol_layer::message::extended::Extended;
use usbpd::protocol_layer::message::{Message, Payload};

// Use uom for nice formatting
use uom::si::electric_current::ampere;
use uom::si::electric_potential::volt;
use uom::si::power::watt;

struct PdDecoder {
    source_caps: Option<SourceCapabilities>,
}

impl PdDecoder {
    fn new() -> Self {
        Self { source_caps: None }
    }

    fn handle_connect(&mut self) {
        self.source_caps = None;
    }

    fn decode(&mut self, sop: u8, wire_data: &[u8]) {
        if wire_data.is_empty() {
             return;
        }

        match Message::from_bytes(wire_data) {
            Ok(msg) => {
                let msg_type = msg.header.message_type();
                let msg_id = msg.header.message_id();
                let role = format!(
                    "{:?}/{:?}",
                    msg.header.port_power_role(),
                    msg.header.port_data_role()
                );

                let type_str = format!("{:?}", msg_type);
                println!(
                    "SOP{}: {:<20} (ID={}, ROLE={})",
                    sop, type_str, msg_id, role
                );

                match &msg.payload {
                    Some(Payload::Data(data)) => {
                        match data {
                            Data::SourceCapabilities(caps) => {
                                self.source_caps = Some(caps.clone());
                                println!("             [SPR Source Capabilities]");
                                for (i, pdo) in caps.pdos().iter().enumerate() {
                                    println!("             PDO[{}]: {:?}", i + 1, pdo);
                                }
                            }
                            Data::Request(req) => {
                                self.print_request(req);
                            }
                            Data::EprMode(mode) => {
                                println!("             EPR Mode: {:?}", mode);
                            }
                            Data::Unknown => {
                                 println!("             Unknown Data Message");
                            }
                            _ => {
                                println!("             Data: {:?}", data);
                            }
                        }
                    }
                    Some(Payload::Extended(ext)) => {
                        match ext {
                            Extended::EprSourceCapabilities(pdos) => {
                                // Update caps for subsequent requests (EPR replaces SPR usually for decoding purposes)
                                // Note: We construct a new SourceCapabilities container. 
                                // Warning: usbpd::SourceCapabilities expects heapless::Vec<PowerDataObject, 16>.
                                // But EPR PDos might be more? Actually spec says max 7 usually.
                                // We'll just display them for now to avoid fighting the type system constructors if they aren't public.
                                println!("             [EPR Source Capabilities]");
                                for (i, pdo) in pdos.iter().enumerate() {
                                    println!("             PDO[{}]: {:?}", i + 1, pdo);
                                }
                            }
                            Extended::ExtendedControl(ctrl) => {
                                println!("             Extended Control: {:?}", ctrl);
                            }
                            _ => {
                                println!("             Extended: {:?}", ext);
                            }
                        }
                    }
                    None => {
                        // Control message (GoodCRC, Accept, etc.) - already summarized by type_str
                    }
                }
            }
            Err(e) => {
                println!("SOP{}: Failed to parse: {:?} (Hex: {:02X?})", sop, e, wire_data);
            }
        }
    }

    fn print_request(&self, req: &data::request::PowerSource) {
         use data::request::PowerSource;
         
         match req {
             PowerSource::FixedVariableSupply(p) => {
                 let curr = p.operating_current().get::<ampere>();
                 let max_curr = p.max_operating_current().get::<ampere>();
                 let pos = p.object_position();
                 
                 print!("             RDO: Requesting PDO#{} @ {:.2}A (Max {:.2}A)", pos, curr, max_curr);
                 
                 // Look up Voltage from PDO if available
                 if let Some(caps) = &self.source_caps {
                      // PDO index is 0-based, object_position is 1-based
                      if let Some(pdo) = caps.pdos().get(pos as usize - 1) {
                           use usbpd::protocol_layer::message::data::source_capabilities::PowerDataObject;
                           if let PowerDataObject::FixedSupply(f) = pdo {
                                let v = f.voltage().get::<volt>();
                                print!(" [Matched Fixed PDO: {:.2}V]", v);
                           } else {
                                print!(" [Matched PDO kind: {:?}]", pdo);
                           }
                      }
                 }
                 println!();
             },
             PowerSource::Battery(p) => {
                 let power = p.operating_power().get::<watt>();
                 println!("             RDO: Requesting Battery PDO#{} @ {:.2}W", p.object_position(), power);
             },
             PowerSource::Pps(p) => {
                 let v = p.output_voltage().get::<volt>();
                 let c = p.operating_current().get::<ampere>();
                 println!("             RDO: Requesting PPS PDO#{} @ {:.2}V / {:.2}A", p.object_position(), v, c);
             },
             PowerSource::Avs(p) => {
                 let v = p.output_voltage().get::<volt>();
                 let c = p.operating_current().get::<ampere>();
                 println!("             RDO: Requesting AVS PDO#{} @ {:.2}V / {:.2}A", p.object_position(), v, c);
             },
             PowerSource::Epr { base, avs } => {
                 let v = avs.output_voltage().get::<volt>();
                 let c = avs.operating_current().get::<ampere>();
                 println!("             RDO: Requesting EPR PDO#{} @ {:.2}V / {:.2}A", base.object_position(), v, c);
             },
             PowerSource::Unknown(raw) => {
                 let pos = raw.object_position();
                 print!("             RDO: Requesting PDO#{} (Raw=0x{:08X})", pos, raw.0);
                 
                 if let Some(caps) = &self.source_caps {
                      if let Some(pdo) = caps.pdos().get(pos as usize - 1) {
                           print!(" [Matches PDO: {:?}]", pdo);
                      }
                 }
                 println!();
             }
         }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    
    // We use Vendor interface for speed
    let config = DeviceConfig::vendor_interface();
    let mut device = KM003C::with_config(config).await?;

    println!("============================================================");
    println!("USB PD Negotiation Capture (Rust + usbpd crate)");
    println!("============================================================");
    println!("Connected to KM003C");
    println!("NOW: Disconnect and reconnect your USB-C load!");
    println!("Capturing for 20 seconds... (Press Ctrl+C to stop early)");
    println!("============================================================");

    // Initial drain
    let _ = device.receive_raw().await;

    // Send Connect to ensure we are receiving events
    use km003c_lib::message::Packet;
    device.send(Packet::Connect).await?;

    let start_time = Instant::now();
    let duration = Duration::from_secs(20);
    let mut decoder = PdDecoder::new();

    loop {
        if start_time.elapsed() >= duration {
            break;
        }

        match device.request_pd_data().await {
            Ok(packet) => {
                if let Some(stream) = KM003C::extract_pd_events(&packet) {
                    for event in &stream.events {
                        match &event.data {
                            PdEventData::Connect(_) => {
                                println!("[{}ms] ** CONNECT **", event.timestamp);
                                decoder.handle_connect();
                            }
                            PdEventData::Disconnect(_) => {
                                println!("[{}ms] ** DISCONNECT **", event.timestamp);
                            }
                            PdEventData::PdMessage { sop, wire_data } => {
                                decoder.decode(*sop, wire_data);
                            }
                        }
                    }
                }
            }
            Err(_e) => {}
        }

        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(30)) => {},
            _ = tokio::signal::ctrl_c() => {
                println!("\nInterrupted by user");
                break;
            }
        }
    }

    device.send(Packet::Disconnect).await?;
    println!("\nCapture complete.");

    Ok(())
}
