use km003c_lib::uom::si::time::second;
use km003c_lib::{PdProtocolTraceEventKind, PdTrace, PdTypeCState};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PdTraceCategory {
    TypeCState,
    ProtocolEvent,
    Unknown,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct PdTraceEntry {
    pub(crate) timestamp_seconds: f64,
    pub(crate) category: PdTraceCategory,
    pub(crate) summary: String,
}

pub(crate) fn decode_trace(trace: &PdTrace) -> Vec<PdTraceEntry> {
    let mut entries = Vec::with_capacity(trace.state_events.len() + trace.protocol_events.len());

    entries.extend(trace.state_events.iter().map(|event| {
        let code = u8::from(event.state);
        let (category, label) = match event.state {
            PdTypeCState::Unknown(_) => (PdTraceCategory::Unknown, format!("Unknown state 0x{code:02x}")),
            state => (PdTraceCategory::TypeCState, format!("{state:?} (0x{code:02x})")),
        };

        PdTraceEntry {
            timestamp_seconds: event.timestamp.get::<second>(),
            category,
            summary: format!(
                "[uptime {:>8.0}s] Type-C state: {label}",
                event.timestamp.get::<second>(),
            ),
        }
    }));

    entries.extend(trace.protocol_events.iter().map(|event| {
        let code = u8::from(event.kind);
        let (category, label) = match event.kind {
            PdProtocolTraceEventKind::Unknown(_) => (PdTraceCategory::Unknown, format!("Unknown state 0x{code:02x}")),
            kind => (PdTraceCategory::ProtocolEvent, format!("{kind:?} (0x{code:02x})")),
        };

        PdTraceEntry {
            timestamp_seconds: event.timestamp.get::<second>(),
            category,
            summary: format!(
                "[uptime {:>8.0}s] Protocol trace: {label}",
                event.timestamp.get::<second>(),
            ),
        }
    }));

    entries.sort_by(|left, right| left.timestamp_seconds.total_cmp(&right.timestamp_seconds));
    entries
}

#[cfg(test)]
mod tests {
    use super::*;
    use km003c_lib::uom::si::f64::Time;
    use km003c_lib::{PdTraceProtocolEvent, PdTraceStateEvent};

    #[test]
    fn combines_trace_queues_in_timestamp_order() {
        let trace = PdTrace {
            state_events: vec![PdTraceStateEvent {
                state: PdTypeCState::AttachedSink,
                timestamp: Time::new::<second>(12.0),
            }],
            protocol_events: vec![PdTraceProtocolEvent {
                kind: PdProtocolTraceEventKind::ReceivedMessage,
                timestamp: Time::new::<second>(10.0),
            }],
        };

        let entries = decode_trace(&trace);

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].category, PdTraceCategory::ProtocolEvent);
        assert!(entries[0].summary.contains("ReceivedMessage (0x82)"));
        assert_eq!(entries[1].category, PdTraceCategory::TypeCState);
        assert!(entries[1].summary.contains("AttachedSink (0x17)"));
    }

    #[test]
    fn preserves_unknown_codes_in_display() {
        let trace = PdTrace {
            state_events: vec![PdTraceStateEvent {
                state: PdTypeCState::Unknown(0xfe),
                timestamp: Time::new::<second>(1.0),
            }],
            protocol_events: vec![PdTraceProtocolEvent {
                kind: PdProtocolTraceEventKind::Unknown(0x76),
                timestamp: Time::new::<second>(2.0),
            }],
        };

        let entries = decode_trace(&trace);

        assert!(entries.iter().all(|entry| entry.category == PdTraceCategory::Unknown));
        assert!(entries[0].summary.contains("Unknown state 0xfe"));
        assert!(entries[1].summary.contains("Unknown state 0x76"));
    }
}
