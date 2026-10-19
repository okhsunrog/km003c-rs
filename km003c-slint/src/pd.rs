//! State behind the PD tab: the message log, the sink connection and the power
//! contract being negotiated.

use std::time::Instant;

use km003c_lib::pd::{PdEvent, PdEventData, PdStatus};
use km003c_lib::uom::si::electric_current::ampere;
use km003c_lib::uom::si::electric_potential::volt;
use km003c_lib::{
    PdConnectionTracker, PdContract, PdLogCategory, PdLogEntry, PdLogger, PdTrace, PdTraceCategory, PdTraceEntry,
};

use crate::PdRow;

/// Rows kept in the log; the oldest drop off the start.
pub const MAX_ROWS: usize = 500;

/// Row categories after the PdLogCategory ones; see the colour table in
/// ui/app.slint.
const TRACE_CATEGORY: i32 = 7;
const UNKNOWN_TRACE_CATEGORY: i32 = 8;

/// What a batch of PD events changes in the UI.
pub struct PdUpdate {
    /// New rows, oldest first.
    pub rows: Vec<PdRow>,
    /// The contract line, when it changed.
    pub contract: Option<String>,
}

/// What a status update changes in the UI.
pub struct PdStatusLines {
    pub sink: String,
    pub lines: String,
    /// The contract line, when a detached sink ended the contract.
    pub contract: Option<String>,
}

#[derive(Default)]
pub struct PdState {
    logger: PdLogger,
    tracker: PdConnectionTracker,
    contract: PdContract,
}

impl PdState {
    /// The meter was connected again. The decoder and the sink detection start
    /// over; the contract is kept, marked as seen before, since a sink that
    /// stayed plugged in does not negotiate again.
    pub fn device_reconnected(&mut self) -> String {
        self.logger.reset();
        self.tracker = PdConnectionTracker::default();
        self.contract.device_reconnected();
        self.contract.to_string()
    }

    pub fn events(&mut self, events: &[PdEvent], now: Instant) -> PdUpdate {
        let before = self.contract.clone();
        let rows = events
            .iter()
            .map(|event| {
                match event.data {
                    PdEventData::Connect => self.tracker.observe_event(true, now),
                    PdEventData::Disconnect => self.tracker.observe_event(false, now),
                    PdEventData::PdMessage { .. } => {}
                }
                let entry = self.logger.log_event(event);
                self.contract.observe(&entry);
                row(&entry)
            })
            .collect();
        PdUpdate {
            rows,
            contract: (self.contract != before).then(|| self.contract.to_string()),
        }
    }

    /// Rows for the firmware's Type-C and protocol-engine trace.
    pub fn trace(&self, trace: &PdTrace) -> Vec<PdRow> {
        trace.entries().iter().map(trace_row).collect()
    }

    /// The sink line and the CC/VBUS line for a status update.
    pub fn status(&mut self, status: &PdStatus, now: Instant) -> PdStatusLines {
        self.tracker.observe_status(status, now);
        self.tracker.update(now);
        let before = self.contract.clone();
        self.contract.observe_sink(self.tracker.connected());
        let sink = match self.tracker.connected() {
            Some(true) => "Sink attached",
            Some(false) => "No sink attached",
            None => "Sink: detecting…",
        };
        let lines = format!(
            "CC1 {:.2} V · CC2 {:.2} V · VBUS {:.2} V · IBUS {:.3} A",
            status.cc1.get::<volt>(),
            status.cc2.get::<volt>(),
            status.vbus.get::<volt>(),
            status.ibus.get::<ampere>()
        );
        PdStatusLines {
            sink: sink.to_string(),
            lines,
            contract: (self.contract != before).then(|| self.contract.to_string()),
        }
    }
}

fn row(entry: &PdLogEntry) -> PdRow {
    PdRow {
        time: format!("{:.3} s", entry.timestamp_seconds).into(),
        sop: entry.sop.map(|sop| format!("SOP{sop}")).unwrap_or_default().into(),
        title: entry.title.as_str().into(),
        header: entry.header.clone().unwrap_or_default().into(),
        details: entry.details.join("\n").into(),
        category: category_index(entry.category),
        good_crc: entry.is_good_crc(),
        expanded: false,
    }
}

fn trace_row(entry: &PdTraceEntry) -> PdRow {
    PdRow {
        // One-second resolution: more digits would suggest a precision the
        // firmware does not have.
        time: format!("{:.0} s", entry.timestamp_seconds).into(),
        sop: "FW".into(),
        title: entry.label.as_str().into(),
        header: entry.source.into(),
        details: Default::default(),
        category: match entry.category {
            PdTraceCategory::TypeCState | PdTraceCategory::ProtocolEvent => TRACE_CATEGORY,
            _ => UNKNOWN_TRACE_CATEGORY,
        },
        good_crc: false,
        expanded: false,
    }
}

/// Matches the colour table in ui/app.slint.
fn category_index(category: PdLogCategory) -> i32 {
    match category {
        PdLogCategory::Connect => 0,
        PdLogCategory::Disconnect => 1,
        PdLogCategory::SourceCaps => 2,
        PdLogCategory::Request => 3,
        PdLogCategory::Control => 4,
        PdLogCategory::Extended => 5,
        PdLogCategory::Error => 6,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use km003c_lib::uom::si::f64::Time;
    use km003c_lib::uom::si::time::{millisecond, second};
    use km003c_lib::{PdTraceStateEvent, PdTypeCState};

    fn message(wire_hex: &str) -> PdEvent {
        let wire_data = (0..wire_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&wire_hex[i..i + 2], 16).unwrap())
            .collect();
        PdEvent {
            timestamp: Time::new::<millisecond>(0.0),
            data: PdEventData::PdMessage { sop: 0, wire_data },
        }
    }

    fn negotiate(state: &mut PdState) -> PdUpdate {
        let events = [
            message("a1612c9101082cd102002cc103002cb10400454106003c21dcc0"), // Source_Capabilities
            message("8210dc700323"),                                         // Request PDO#2
            message("a305"),                                                 // Accept
            message("a607"),                                                 // PS_RDY
        ];
        state.events(&events, Instant::now())
    }

    #[test]
    fn a_negotiation_ends_in_an_active_contract() {
        let mut state = PdState::default();
        let update = negotiate(&mut state);

        assert_eq!(update.rows.len(), 4);
        assert_eq!(update.rows[0].title, "Source_Capabilities");
        assert_eq!(update.rows[0].category, 2);
        assert_eq!(update.contract.as_deref(), Some("PDO#2 (Fixed 9V @ 3.0A (27W)) @ 2.2A"));
    }

    #[test]
    fn the_contract_outlives_a_meter_reconnect() {
        let mut state = PdState::default();
        negotiate(&mut state);

        let contract = state.device_reconnected();

        assert_eq!(
            contract,
            "PDO#2 (Fixed 9V @ 3.0A (27W)) @ 2.2A · seen before reconnecting"
        );
    }

    #[test]
    fn good_crc_rows_are_flagged_for_hiding() {
        let update = PdState::default().events(&[message("4102")], Instant::now());
        assert!(update.rows[0].good_crc);
    }

    #[test]
    fn trace_entries_become_firmware_rows() {
        let trace = PdTrace {
            state_events: vec![PdTraceStateEvent {
                state: PdTypeCState::AttachedSink,
                timestamp: Time::new::<second>(12.0),
            }],
            protocol_events: Vec::new(),
        };

        let rows = PdState::default().trace(&trace);

        assert_eq!(rows[0].sop, "FW");
        assert_eq!(rows[0].title, "AttachedSink (0x17)");
        assert_eq!(rows[0].header, "Type-C state");
        assert_eq!(rows[0].category, TRACE_CATEGORY);
    }
}
