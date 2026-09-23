//! A long-running streaming session for graphical front ends.
//!
//! [`Session::spawn`] starts a task that finds the device, authenticates it,
//! keeps AdcQueue and PD streaming, and pauses streaming around offline-log
//! access. The front end sends commands through the [`Session`] handle and
//! receives [`SessionEvent`]s on a channel, so it never blocks on USB I/O.
//!
//! Where enumeration is unavailable, such as on Android, open the device
//! yourself and hand it over with [`Session::connect_device`].

use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::device::{PID, VID};
use crate::error::KMError;
use crate::packet::{Attribute, AttributeSet};
use crate::pd::{PdEvent, PdStatus};
use crate::{AdcQueueSample, DeviceConfig, DeviceState, GraphSampleRate, KM003C, LogMetadata, OfflineLog, PdTrace};

/// Consecutive request failures that end a streaming session.
const MAX_ERRORS: u32 = 10;

/// What the session task reports to the front end.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum SessionEvent {
    /// Discovery is waiting for a USB hotplug event.
    WaitingForDevice,
    /// Device connected and initialized.
    Connected(Arc<DeviceState>),
    /// Connection failed.
    ConnectionFailed { error: String, retry_when_present: bool },
    /// New AdcQueue samples.
    Samples(Vec<AdcQueueSample>),
    /// PD events from the device's PD monitor.
    PdEvents(Vec<PdEvent>),
    /// PD status (CC line voltages).
    PdStatusUpdate(PdStatus),
    /// Firmware Type-C and protocol-engine trace.
    PdTrace(PdTrace),
    /// Device offline-recording catalog.
    OfflineCatalog(Vec<LogMetadata>),
    /// Complete selected offline recording.
    OfflineLogDownloaded(OfflineLog),
    /// An offline catalog or download operation failed.
    OfflineOperationFailed(String),
    /// Streaming started at the given rate.
    StreamingStarted(GraphSampleRate),
    /// Streaming stopped.
    StreamingStopped,
    /// Error during streaming.
    Error(String),
    /// Streaming ended. Reconnect only after an unexpected transport loss.
    Disconnected { retry_when_present: bool },
}

/// A request to the session task. Front ends normally use the [`Session`]
/// methods; the type is public so tests can inspect what a UI sent.
#[derive(Debug)]
#[non_exhaustive]
pub enum SessionCommand {
    /// Find the device, connect and start streaming.
    Connect { rate: GraphSampleRate, usb_reset: bool },
    /// Connect to a device the caller has already opened, and start streaming.
    ConnectDevice {
        device: nusb::Device,
        rate: GraphSampleRate,
    },
    /// Change the sample rate (restarts streaming).
    SetSampleRate(GraphSampleRate),
    /// Enable or disable firmware PD trace collection.
    SetPdTraceEnabled(bool),
    /// Fetch the catalog of recordings stored by the device.
    RequestOfflineCatalog,
    /// Download one catalog entry from device memory.
    DownloadOfflineLog(LogMetadata),
    /// Stop streaming and disconnect.
    Disconnect,
}

/// The session task has stopped, so the command was not delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("the KM003C session task has stopped")]
pub struct SessionClosed;

/// Handle for sending commands to a session task.
#[derive(Debug, Clone)]
pub struct Session {
    commands: mpsc::UnboundedSender<SessionCommand>,
}

impl Session {
    /// Spawn the session task on the current Tokio runtime.
    ///
    /// # Panics
    ///
    /// Panics when called outside a Tokio runtime.
    pub fn spawn() -> (Self, mpsc::UnboundedReceiver<SessionEvent>) {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        tokio::spawn(run(event_tx, command_rx));
        (Self { commands: command_tx }, event_rx)
    }

    /// A handle with no task behind it; commands go to the returned receiver.
    ///
    /// Use it to drive a front end in tests without a device.
    pub fn detached() -> (Self, mpsc::UnboundedReceiver<SessionCommand>) {
        let (commands, receiver) = mpsc::unbounded_channel();
        (Self { commands }, receiver)
    }

    fn send(&self, command: SessionCommand) -> Result<(), SessionClosed> {
        self.commands.send(command).map_err(|_| SessionClosed)
    }

    /// Find the device, connect and start streaming. Discovery waits for the
    /// device to be plugged in.
    pub fn connect(&self, rate: GraphSampleRate, usb_reset: bool) -> Result<(), SessionClosed> {
        self.send(SessionCommand::Connect { rate, usb_reset })
    }

    /// Connect to an already opened device and start streaming.
    pub fn connect_device(&self, device: nusb::Device, rate: GraphSampleRate) -> Result<(), SessionClosed> {
        self.send(SessionCommand::ConnectDevice { device, rate })
    }

    pub fn set_sample_rate(&self, rate: GraphSampleRate) -> Result<(), SessionClosed> {
        self.send(SessionCommand::SetSampleRate(rate))
    }

    pub fn set_pd_trace_enabled(&self, enabled: bool) -> Result<(), SessionClosed> {
        self.send(SessionCommand::SetPdTraceEnabled(enabled))
    }

    pub fn request_offline_catalog(&self) -> Result<(), SessionClosed> {
        self.send(SessionCommand::RequestOfflineCatalog)
    }

    pub fn download_offline_log(&self, metadata: LogMetadata) -> Result<(), SessionClosed> {
        self.send(SessionCommand::DownloadOfflineLog(metadata))
    }

    pub fn disconnect(&self) -> Result<(), SessionClosed> {
        self.send(SessionCommand::Disconnect)
    }
}

/// The session task. [`Session::spawn`] runs it; call it directly to run the
/// session on an executor of your choice.
pub async fn run(tx: mpsc::UnboundedSender<SessionEvent>, mut cmd_rx: mpsc::UnboundedReceiver<SessionCommand>) {
    info!("Session task started, waiting for a connect command");

    while let Some(command) = cmd_rx.recv().await {
        match command {
            SessionCommand::Connect { rate, usb_reset } => {
                debug!("Connect command received, rate={rate:?}, reset={usb_reset}");
                if let Some((device, rate)) = discover_and_open(&tx, &mut cmd_rx, rate, usb_reset).await {
                    stream(device, &tx, &mut cmd_rx, rate).await;
                }
            }
            SessionCommand::ConnectDevice { device, rate } => {
                debug!("Connecting to a caller-opened device, rate={rate:?}");
                match KM003C::from_device(device, DeviceConfig::vendor()).await {
                    Ok(device) => {
                        if let Some(device) = announce(device, &tx) {
                            stream(device, &tx, &mut cmd_rx, rate).await;
                        }
                    }
                    Err(error) => report_connection_failure(&tx, &error),
                }
            }
            SessionCommand::Disconnect => {
                let _ = tx.send(SessionEvent::Disconnected {
                    retry_when_present: false,
                });
            }
            command => debug!("Ignoring command while disconnected: {command:?}"),
        }
    }
    warn!("Command channel closed");
}

/// Subscribe before enumerating so an attachment cannot fall between the two.
/// No device handles are opened and no periodic probes run while waiting.
async fn wait_for_device(tx: &mpsc::UnboundedSender<SessionEvent>) -> Result<(), KMError> {
    let is_km003c = |vendor_id: u16, product_id: u16| vendor_id == VID && product_id == PID;
    let mut watch = nusb::watch_devices()?;
    let mut announced = false;
    loop {
        if nusb::list_devices()
            .await?
            .any(|device| is_km003c(device.vendor_id(), device.product_id()))
        {
            return Ok(());
        }
        if !announced {
            let _ = tx.send(SessionEvent::WaitingForDevice);
            announced = true;
        }
        loop {
            match watch.next().await {
                Some(nusb::hotplug::HotplugEvent::Connected(device))
                    if is_km003c(device.vendor_id(), device.product_id()) =>
                {
                    // Let interface creation and device permissions settle.
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    break;
                }
                Some(_) => {}
                None => return Err(KMError::Protocol("USB hotplug watcher closed".to_string())),
            }
        }
    }
}

/// Whether an error means the device went away rather than misbehaved.
pub fn is_device_disconnect(error: &KMError) -> bool {
    match error {
        KMError::DeviceNotFound => true,
        KMError::Usb(error) => error.kind() == nusb::ErrorKind::Disconnected,
        KMError::Io(error) => matches!(
            error.kind(),
            std::io::ErrorKind::NotConnected | std::io::ErrorKind::ConnectionAborted
        ),
        _ => false,
    }
}

fn report_connection_failure(tx: &mpsc::UnboundedSender<SessionEvent>, error: &KMError) {
    if is_device_disconnect(error) {
        debug!("Device removed during connection: {error}");
    } else {
        error!("Failed to connect: {error}");
    }
    let _ = tx.send(SessionEvent::ConnectionFailed {
        retry_when_present: is_device_disconnect(error),
        error: error.to_string(),
    });
}

/// Wait for the device, then open it. Returns `None` when the session ended
/// or the connection failed; the reason has already been reported.
async fn discover_and_open(
    tx: &mpsc::UnboundedSender<SessionEvent>,
    cmd_rx: &mut mpsc::UnboundedReceiver<SessionCommand>,
    mut rate: GraphSampleRate,
    mut usb_reset: bool,
) -> Option<(KM003C, GraphSampleRate)> {
    loop {
        tokio::select! {
            biased;
            command = cmd_rx.recv() => match command {
                Some(SessionCommand::Disconnect) | None => {
                    let _ = tx.send(SessionEvent::Disconnected { retry_when_present: false });
                    return None;
                }
                Some(SessionCommand::Connect { rate: new_rate, usb_reset: reset }) => {
                    rate = new_rate;
                    usb_reset = reset;
                }
                Some(SessionCommand::SetSampleRate(new_rate)) => rate = new_rate,
                Some(_) => {}
            },
            _ = tx.closed() => return None,
            result = wait_for_device(tx) => {
                if let Err(error) = result {
                    error!("USB discovery failed: {error}");
                    let _ = tx.send(SessionEvent::ConnectionFailed {
                        error: error.to_string(),
                        retry_when_present: false,
                    });
                    return None;
                }
                break;
            }
        }
    }

    // Vendor interface (Full mode) is required for AdcQueue.
    let config = if usb_reset {
        DeviceConfig::vendor()
    } else {
        DeviceConfig::vendor().skip_reset()
    };
    match KM003C::new(config).await {
        Ok(device) => announce(device, tx).map(|device| (device, rate)),
        Err(error) => {
            report_connection_failure(tx, &error);
            None
        }
    }
}

/// Report the connected device, or refuse one that cannot stream.
fn announce(device: KM003C, tx: &mpsc::UnboundedSender<SessionEvent>) -> Option<KM003C> {
    let state = device.state().expect("device in Full mode");
    info!("Connected to {} (FW {})", state.model(), state.firmware_version());

    if !state.adcqueue_enabled {
        error!("AdcQueue not enabled - authentication may have failed");
        let _ = tx.send(SessionEvent::ConnectionFailed {
            error: "AdcQueue not enabled".to_string(),
            retry_when_present: false,
        });
        return None;
    }

    let _ = tx.send(SessionEvent::Connected(Arc::new(state.clone())));
    Some(device)
}

async fn stream(
    mut device: KM003C,
    tx: &mpsc::UnboundedSender<SessionEvent>,
    cmd_rx: &mut mpsc::UnboundedReceiver<SessionCommand>,
    initial_rate: GraphSampleRate,
) {
    // Initial StopGraph to ensure clean state
    info!("Sending initial StopGraph to ensure clean state");
    let _ = device.stop_graph_mode().await;

    let mut current_rate = initial_rate;
    if let Err(e) = start_streaming(&mut device, current_rate, tx).await {
        error!("Failed to start streaming: {}", e);
        let _ = tx.send(SessionEvent::Disconnected {
            retry_when_present: is_device_disconnect(&e),
        });
        if !is_device_disconnect(&e) {
            let _ = tx.send(SessionEvent::Error(format!("Start failed: {e}")));
        }
        return;
    }

    let mut error_count = 0;
    let mut pd_trace_enabled = false;
    let mut reconnect_when_present = false;
    let mut terminal_error = None;

    loop {
        // Check for commands from the UI (non-blocking)
        match cmd_rx.try_recv() {
            Ok(SessionCommand::SetSampleRate(new_rate)) => {
                if new_rate != current_rate {
                    info!("Changing sample rate to {:?}", new_rate);

                    if let Err(error) = device.stop_graph_mode().await {
                        reconnect_when_present = is_device_disconnect(&error);
                        terminal_error = Some(format!("Failed to stop streaming for rate change: {error}"));
                        break;
                    }
                    let _ = tx.send(SessionEvent::StreamingStopped);

                    if let Err(e) = start_streaming(&mut device, new_rate, tx).await {
                        error!("Failed to restart streaming: {}", e);
                        reconnect_when_present = is_device_disconnect(&e);
                        terminal_error = Some(format!("Restart failed: {e}"));
                        break;
                    }
                    current_rate = new_rate;
                }
            }
            Ok(SessionCommand::SetPdTraceEnabled(enabled)) => {
                pd_trace_enabled = enabled;
                info!(
                    "Firmware PD trace collection {}",
                    if enabled { "enabled" } else { "disabled" }
                );
            }
            Ok(SessionCommand::RequestOfflineCatalog) => {
                info!("Loading offline recording catalog");
                if let Err(error) = device.stop_graph_mode().await {
                    let _ = tx.send(SessionEvent::OfflineOperationFailed(format!(
                        "Could not pause streaming for offline catalog access: {error}"
                    )));
                    continue;
                }
                let _ = tx.send(SessionEvent::StreamingStopped);
                match device.request_log_metadata().await {
                    Ok(catalog) => {
                        let _ = tx.send(SessionEvent::OfflineCatalog(catalog));
                    }
                    Err(error) => {
                        let _ = tx.send(SessionEvent::OfflineOperationFailed(format!(
                            "Failed to load offline catalog: {error}"
                        )));
                    }
                }
                if let Err(error) = start_streaming(&mut device, current_rate, tx).await {
                    reconnect_when_present = is_device_disconnect(&error);
                    terminal_error = Some(format!(
                        "Failed to resume streaming after loading offline catalog: {error}"
                    ));
                    break;
                }
            }
            Ok(SessionCommand::DownloadOfflineLog(metadata)) => {
                info!(
                    filename = %metadata.filename_lossy(),
                    samples = metadata.sample_count,
                    "Downloading offline recording"
                );
                if let Err(error) = device.stop_graph_mode().await {
                    let _ = tx.send(SessionEvent::OfflineOperationFailed(format!(
                        "Could not pause streaming for offline download: {error}"
                    )));
                    continue;
                }
                let _ = tx.send(SessionEvent::StreamingStopped);
                match device.download_offline_log(metadata).await {
                    Ok(log) => {
                        let _ = tx.send(SessionEvent::OfflineLogDownloaded(log));
                    }
                    Err(error) => {
                        let _ = tx.send(SessionEvent::OfflineOperationFailed(format!(
                            "Failed to download offline recording: {error}"
                        )));
                    }
                }
                if let Err(error) = start_streaming(&mut device, current_rate, tx).await {
                    reconnect_when_present = is_device_disconnect(&error);
                    terminal_error = Some(format!("Failed to resume streaming after offline download: {error}"));
                    break;
                }
            }
            Ok(SessionCommand::Disconnect) => {
                info!("Disconnect command received");
                reconnect_when_present = false;
                break;
            }
            Ok(command @ (SessionCommand::Connect { .. } | SessionCommand::ConnectDevice { .. })) => {
                debug!("Ignoring {command:?} while already streaming");
            }
            Err(mpsc::error::TryRecvError::Empty) => {}
            Err(mpsc::error::TryRecvError::Disconnected) => {
                warn!("Command channel disconnected");
                reconnect_when_present = false;
                break;
            }
        }

        // Request the regular streams and the opt-in firmware trace.
        let mask = streaming_attribute_mask(pd_trace_enabled);
        match device.request_data(mask).await {
            Ok(packet) => {
                error_count = 0;

                if let Some(queue_data) = packet.get_adc_queue()
                    && !queue_data.samples.is_empty()
                {
                    debug!("Received {} samples", queue_data.samples.len());
                    if tx.send(SessionEvent::Samples(queue_data.samples.clone())).is_err() {
                        warn!("UI closed, stopping");
                        break;
                    }
                }

                if let Some(stream) = packet.get_pd_events() {
                    let _ = tx.send(SessionEvent::PdStatusUpdate(stream.preamble));
                    let _ = tx.send(SessionEvent::PdEvents(stream.events.clone()));
                }
                if let Some(status) = packet.get_pd_status() {
                    let _ = tx.send(SessionEvent::PdStatusUpdate(*status));
                }
                if let Some(trace) = packet.get_pd_trace()
                    && (!trace.state_events.is_empty() || !trace.protocol_events.is_empty())
                {
                    let _ = tx.send(SessionEvent::PdTrace(trace.clone()));
                }
            }
            Err(e) => {
                error_count += 1;
                debug!("Request error: {}", e);
                if is_device_disconnect(&e) {
                    reconnect_when_present = true;
                    break;
                }
                if error_count >= MAX_ERRORS {
                    terminal_error = Some(format!("Streaming failed after {MAX_ERRORS} errors: {e}"));
                    break;
                }
            }
        }

        // Poll often enough that the device queue never overflows.
        let delay_ms = match current_rate {
            GraphSampleRate::Sps2 => 200,  // 5 requests/sec for 2 SPS
            GraphSampleRate::Sps10 => 50,  // 20 requests/sec for 10 SPS
            GraphSampleRate::Sps50 => 20,  // 50 requests/sec for 50 SPS
            GraphSampleRate::Sps1000 => 5, // 200 requests/sec for 1000 SPS
        };
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
    }

    info!("Stopping streaming");
    let _ = device.stop_graph_mode().await;
    let _ = tx.send(SessionEvent::Disconnected {
        retry_when_present: reconnect_when_present,
    });
    if !reconnect_when_present && let Some(error) = terminal_error {
        let _ = tx.send(SessionEvent::Error(error));
    }
}

fn streaming_attribute_mask(pd_trace_enabled: bool) -> AttributeSet {
    let mask = AttributeSet::single(Attribute::AdcQueue).with(Attribute::PdPacket);
    if pd_trace_enabled {
        mask.with(Attribute::PdTrace)
    } else {
        mask
    }
}

async fn start_streaming(
    device: &mut KM003C,
    rate: GraphSampleRate,
    tx: &mpsc::UnboundedSender<SessionEvent>,
) -> Result<(), KMError> {
    info!("Starting AdcQueue streaming at {:?}", rate);
    device.start_graph_mode(rate).await?;
    let _ = tx.send(SessionEvent::StreamingStarted(rate));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firmware_trace_is_only_requested_when_enabled() {
        let disabled = streaming_attribute_mask(false);
        assert!(disabled.contains(Attribute::AdcQueue));
        assert!(disabled.contains(Attribute::PdPacket));
        assert!(!disabled.contains(Attribute::PdTrace));

        let enabled = streaming_attribute_mask(true);
        assert!(enabled.contains(Attribute::AdcQueue));
        assert!(enabled.contains(Attribute::PdPacket));
        assert!(enabled.contains(Attribute::PdTrace));
    }

    #[test]
    fn detached_session_forwards_commands() {
        let (session, mut commands) = Session::detached();
        session.set_sample_rate(GraphSampleRate::Sps1000).unwrap();

        assert!(matches!(
            commands.try_recv(),
            Ok(SessionCommand::SetSampleRate(GraphSampleRate::Sps1000))
        ));
        drop(commands);
        assert_eq!(session.disconnect(), Err(SessionClosed));
    }
}
