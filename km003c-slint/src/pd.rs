//! State behind the PD tab: the message log, the sink connection and the power
//! contract being negotiated.

use std::time::Instant;

use km003c_lib::pd::{PdEvent, PdEventData, PdStatus};
use km003c_lib::uom::si::electric_current::ampere;
use km003c_lib::uom::si::electric_potential::volt;
use km003c_lib::{PdConnectionTracker, PdLogCategory, PdLogEntry, PdLogger};

use crate::PdRow;

/// Rows kept in the log; the oldest drop off the start.
pub const MAX_ROWS: usize = 500;

/// What a batch of PD events changes in the UI.
pub struct PdUpdate {
    /// New rows, oldest first.
    pub rows: Vec<PdRow>,
    /// The contract line, when it changed.
    pub contract: Option<String>,
}

#[derive(Default)]
pub struct PdState {
    logger: PdLogger,
    tracker: PdConnectionTracker,
    contract: Contract,
}

impl PdState {
    /// Forget everything about the previous device connection.
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    pub fn events(&mut self, events: &[PdEvent], now: Instant) -> PdUpdate {
        let before = self.contract.describe();
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
        let after = self.contract.describe();
        PdUpdate {
            rows,
            contract: (after != before).then_some(after),
        }
    }

    /// The sink line and the CC/VBUS line for a status update.
    pub fn status(&mut self, status: &PdStatus, now: Instant) -> (String, String) {
        self.tracker.observe_status(status, now);
        self.tracker.update(now);
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
        (sink.to_string(), lines)
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

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum Stage {
    #[default]
    None,
    Offered,
    Requested,
    Accepted,
    Rejected,
    Active,
}

/// The power contract as the negotiation messages establish it.
#[derive(Debug, Default)]
struct Contract {
    request: Option<String>,
    stage: Stage,
}

impl Contract {
    fn observe(&mut self, entry: &PdLogEntry) {
        match (entry.category, entry.title.as_str()) {
            (PdLogCategory::Connect | PdLogCategory::Disconnect, _) | (_, "Soft_Reset") => *self = Self::default(),
            (PdLogCategory::Request, _) => {
                self.request = entry
                    .details
                    .first()
                    .map(|detail| detail.strip_prefix("RDO: ").unwrap_or(detail).to_string());
                self.stage = Stage::Requested;
            }
            (_, "Source_Capabilities" | "EPR_Source_Capabilities") => {
                *self = Self {
                    request: None,
                    stage: Stage::Offered,
                };
            }
            (_, "Accept") if self.stage == Stage::Requested => self.stage = Stage::Accepted,
            (_, "Reject") if self.stage == Stage::Requested => self.stage = Stage::Rejected,
            (_, "PS_RDY") if self.stage == Stage::Accepted => self.stage = Stage::Active,
            _ => {}
        }
    }

    fn describe(&self) -> String {
        let request = self.request.as_deref().unwrap_or("request");
        match self.stage {
            Stage::None => "—".to_string(),
            Stage::Offered => "source capabilities offered".to_string(),
            Stage::Requested => format!("{request} · requested"),
            Stage::Accepted => format!("{request} · accepted, waiting for PS_RDY"),
            Stage::Rejected => format!("{request} · rejected"),
            Stage::Active => request.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use km003c_lib::uom::si::f64::Time;
    use km003c_lib::uom::si::time::millisecond;

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

    #[test]
    fn a_negotiation_ends_in_an_active_contract() {
        let mut state = PdState::default();
        let events = [
            message("a1612c9101082cd102002cc103002cb10400454106003c21dcc0"), // Source_Capabilities
            message("8210dc700323"),                                         // Request PDO#2
            message("a305"),                                                 // Accept
            message("a607"),                                                 // PS_RDY
        ];

        let update = state.events(&events, Instant::now());

        assert_eq!(update.rows.len(), 4);
        assert_eq!(update.rows[0].title, "Source_Capabilities");
        assert_eq!(update.rows[0].category, 2);
        assert_eq!(update.contract.as_deref(), Some("PDO#2 (Fixed 9V @ 3.0A (27W)) @ 2.2A"));
    }

    #[test]
    fn a_disconnect_clears_the_contract() {
        let mut state = PdState::default();
        state.events(&[message("8210dc700323")], Instant::now());

        let update = state.events(
            &[PdEvent {
                timestamp: Time::new::<millisecond>(0.0),
                data: PdEventData::Disconnect,
            }],
            Instant::now(),
        );

        assert_eq!(update.contract.as_deref(), Some("—"));
        assert_eq!(update.rows[0].sop, "");
    }

    #[test]
    fn good_crc_rows_are_flagged_for_hiding() {
        let update = PdState::default().events(&[message("4102")], Instant::now());
        assert!(update.rows[0].good_crc);
    }
}
