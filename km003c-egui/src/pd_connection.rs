use std::time::{Duration, Instant};

use km003c_lib::pd::PdStatus;
use km003c_lib::uom::si::electric_potential::volt;

// On the KM003C's downstream/source-facing CC pins, an attached sink's Rd
// pulls the active line into the Type-C detection range. An open source CC
// line instead sits near 3.2 V, while an unpowered line sits near 0 V.
const CONNECT_MIN_V: f64 = 0.20;
const CONNECT_MAX_V: f64 = 2.45;
const DISCONNECT_LOW_V: f64 = 0.10;
const DISCONNECT_HIGH_V: f64 = 2.75;
const CONNECTION_DEBOUNCE: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, Copy)]
struct PendingState {
    connected: bool,
    since: Instant,
}

/// Stable phone connection state derived from PD events or, until the first
/// connection event arrives, debounced CC voltage measurements.
#[derive(Debug, Default)]
pub struct PdConnectionTracker {
    connected: Option<bool>,
    pending: Option<PendingState>,
    received_connection_event: bool,
}

impl PdConnectionTracker {
    pub fn connected(&self) -> Option<bool> {
        self.connected
    }

    pub fn observe_status(&mut self, status: &PdStatus, now: Instant) {
        self.observe_status_voltages(status.cc1.get::<volt>(), status.cc2.get::<volt>(), now);
    }

    fn observe_status_voltages(&mut self, cc1_v: f64, cc2_v: f64, now: Instant) {
        if self.received_connection_event {
            return;
        }

        let active_cc_v = cc1_v.max(cc2_v);
        let candidate = if (CONNECT_MIN_V..=CONNECT_MAX_V).contains(&active_cc_v) {
            Some(true)
        } else if active_cc_v <= DISCONNECT_LOW_V || active_cc_v >= DISCONNECT_HIGH_V {
            Some(false)
        } else {
            None
        };

        if let Some(candidate) = candidate {
            self.observe_candidate(candidate, now);
        } else {
            self.pending = None;
        }
    }

    pub fn observe_event(&mut self, connected: bool, now: Instant) {
        self.received_connection_event = true;
        self.observe_candidate(connected, now);
    }

    pub fn update(&mut self, now: Instant) {
        let Some(pending) = self.pending else {
            return;
        };

        if now.saturating_duration_since(pending.since) >= CONNECTION_DEBOUNCE {
            self.connected = Some(pending.connected);
            self.pending = None;
        }
    }

    fn observe_candidate(&mut self, connected: bool, now: Instant) {
        if self.connected == Some(connected) {
            self.pending = None;
            return;
        }

        if self.pending.is_none_or(|pending| pending.connected != connected) {
            self.pending = Some(PendingState { connected, since: now });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn advance(start: Instant, millis: u64) -> Instant {
        start + Duration::from_millis(millis)
    }

    fn settle_voltages(tracker: &mut PdConnectionTracker, cc1_v: f64, cc2_v: f64, start: Instant) {
        tracker.observe_status_voltages(cc1_v, cc2_v, start);
        tracker.update(advance(start, 100));
    }

    #[test]
    fn ignores_a_short_cc_disconnect_spike() {
        let start = Instant::now();
        let mut tracker = PdConnectionTracker::default();
        settle_voltages(&mut tracker, 1.65, 0.0, start);
        assert_eq!(tracker.connected(), Some(true));

        tracker.observe_status_voltages(3.21, 0.0, advance(start, 110));
        tracker.observe_status_voltages(1.65, 0.0, advance(start, 150));
        tracker.update(advance(start, 250));

        assert_eq!(tracker.connected(), Some(true));
    }

    #[test]
    fn accepts_a_sustained_cc_disconnect() {
        let start = Instant::now();
        let mut tracker = PdConnectionTracker::default();
        settle_voltages(&mut tracker, 1.65, 0.0, start);
        assert_eq!(tracker.connected(), Some(true));

        tracker.observe_status_voltages(3.21, 0.0, advance(start, 110));
        tracker.update(advance(start, 210));

        assert_eq!(tracker.connected(), Some(false));
    }

    #[test]
    fn connection_events_take_priority_over_cc_voltage() {
        let start = Instant::now();
        let mut tracker = PdConnectionTracker::default();
        settle_voltages(&mut tracker, 1.65, 0.0, start);
        assert_eq!(tracker.connected(), Some(true));

        tracker.observe_event(false, advance(start, 110));
        tracker.observe_status_voltages(1.65, 0.0, advance(start, 150));
        tracker.update(advance(start, 210));

        assert_eq!(tracker.connected(), Some(false));
    }

    #[test]
    fn debounces_contradictory_connection_events() {
        let start = Instant::now();
        let mut tracker = PdConnectionTracker::default();
        settle_voltages(&mut tracker, 1.65, 0.0, start);
        assert_eq!(tracker.connected(), Some(true));

        tracker.observe_event(false, advance(start, 110));
        tracker.observe_event(true, advance(start, 150));
        tracker.update(advance(start, 250));

        assert_eq!(tracker.connected(), Some(true));
    }

    #[test]
    fn recorded_open_source_cc_is_not_a_connected_sink() {
        let start = Instant::now();
        let mut tracker = PdConnectionTracker::default();

        settle_voltages(&mut tracker, 3.237, 0.125, start);

        assert_eq!(tracker.connected(), Some(false));
    }

    #[test]
    fn recorded_rd_voltage_is_a_connected_sink() {
        let start = Instant::now();
        let mut tracker = PdConnectionTracker::default();

        settle_voltages(&mut tracker, 1.654, 0.002, start);

        assert_eq!(tracker.connected(), Some(true));
    }

    #[test]
    fn unpowered_cc_lines_are_not_connected() {
        let start = Instant::now();
        let mut tracker = PdConnectionTracker::default();

        settle_voltages(&mut tracker, 0.0, 0.0, start);

        assert_eq!(tracker.connected(), Some(false));
    }
}
