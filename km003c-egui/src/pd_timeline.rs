//! Bounded, loss-aware presentation of repetitive PD diagnostics.
use km003c_lib::{PdLogCategory, PdLogEntry};
use std::{collections::VecDeque, ops::Deref};

pub struct PdLogRow {
    pub entry: PdLogEntry,
    pub first_timestamp: f64,
    pub count: u64,
    pub latest_raw: Option<String>,
}

impl From<PdLogEntry> for PdLogRow {
    fn from(entry: PdLogEntry) -> Self {
        Self {
            first_timestamp: entry.timestamp_seconds,
            entry,
            count: 1,
            latest_raw: None,
        }
    }
}

impl Deref for PdLogRow {
    type Target = PdLogEntry;
    fn deref(&self) -> &Self::Target {
        &self.entry
    }
}

impl PdLogRow {
    pub fn summary(&self) -> String {
        if self.count == 1 {
            self.entry.summary()
        } else {
            format!(
                "{} · ×{} since {:.3}s",
                self.entry.summary(),
                self.count,
                self.first_timestamp
            )
        }
    }
}

pub fn push(log: &mut VecDeque<PdLogRow>, entry: PdLogEntry, capacity: usize) {
    if matches!(entry.category, PdLogCategory::Error | PdLogCategory::Diagnostic)
        && let Some(row) = log.iter_mut().rev().take(64).find(|row| {
            row.category == entry.category
                && row.sop == entry.sop
                && row.title == entry.title
                && (if entry.category == PdLogCategory::Diagnostic {
                    row.details.first() == entry.details.first()
                } else {
                    row.details == entry.details
                })
                && row.header == entry.header
                && (0.0..=2.0).contains(&(entry.timestamp_seconds - row.timestamp_seconds))
        })
    {
        row.count += 1;
        if entry.category == PdLogCategory::Diagnostic {
            row.latest_raw = entry.details.get(1).cloned();
        }
        row.entry.timestamp_seconds = entry.timestamp_seconds;
        return;
    }
    log.push_back(entry.into());
    while log.len() > capacity {
        log.pop_front();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn diagnostic(time: f64, raw: &str) -> PdLogEntry {
        PdLogEntry {
            timestamp_seconds: time,
            category: PdLogCategory::Diagnostic,
            sop: None,
            title: "Device status 0x02".into(),
            header: None,
            details: vec!["Flags: 00".into(), raw.into()],
        }
    }
    #[test]
    fn errors_only_group_when_the_original_payload_matches() {
        let mut log = VecDeque::new();
        let error = |time, raw: &str| PdLogEntry {
            timestamp_seconds: time,
            category: PdLogCategory::Error,
            sop: Some(0),
            title: "Parse error".into(),
            header: None,
            details: vec![raw.into()],
        };
        push(&mut log, error(0.0, "01 02"), 10);
        push(&mut log, error(0.1, "01 02"), 10);
        push(&mut log, error(0.2, "01 03"), 10);
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].count, 2);
        assert_eq!(log[1].details, ["01 03"]);
    }

    #[test]
    fn repeated_diagnostics_keep_counts_time_span_and_distinct_raw_payloads() {
        let mut log = VecDeque::new();
        for i in 0..1000 {
            push(
                &mut log,
                diagnostic(i as f64 / 10.0, &format!("45 {i} 00 00 00 02")),
                100,
            );
        }
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].count, 1000);
        assert_eq!(log[0].first_timestamp, 0.0);
        assert_eq!(log[0].timestamp_seconds, 99.9);
        assert_eq!(log[0].latest_raw.as_deref(), Some("45 999 00 00 00 02"));
        assert_eq!(log[0].details[1], "45 0 00 00 00 02");
        let mut different = diagnostic(100.0, "45 01 00 00 80 02");
        different.details[0] = "Flags: 80".into();
        push(&mut log, different, 100);
        assert_eq!(log.len(), 2, "different raw payloads must not be lost");
    }
}
