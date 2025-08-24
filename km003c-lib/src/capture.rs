

use serde::{Deserialize, Serialize};
use std::path::Path;

/// USB direction enum
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UsbDirection {
    HostToDevice, // H->D
    DeviceToHost, // D->H
}

impl std::fmt::Display for UsbDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UsbDirection::HostToDevice => write!(f, "H->D"),
            UsbDirection::DeviceToHost => write!(f, "D->H"),
        }
    }
}

/// Raw capture data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawCapture {
    pub session_id: String,      // e.g., "orig_adc_1000hz.6"
    pub timestamp: f64,          // from frame.time_relative
    pub direction: UsbDirection, // H->D or D->H
    pub raw_bytes: Vec<u8>,      // the actual USB data
    pub frame_number: u32,       // from frame.number
    pub added_datetime: String,  // ISO 8601 datetime when this row was added
}

impl RawCapture {
    /// Create a new raw capture entry
    pub fn new(
        session_id: String,
        timestamp: f64,
        direction: UsbDirection,
        raw_bytes: Vec<u8>,
        frame_number: u32,
        added_datetime: String,
    ) -> Self {
        Self {
            session_id,
            timestamp,
            direction,
            raw_bytes,
            frame_number,
            added_datetime,
        }
    }

    /// Get the raw bytes as a hex string
    pub fn hex_string(&self) -> String {
        hex::encode(&self.raw_bytes)
    }
}

/// Collection of raw captures with parquet save/load functionality
pub struct CaptureCollection {
    captures: Vec<RawCapture>,
}

impl CaptureCollection {
    /// Create a new empty collection
    pub fn new() -> Self {
        Self { captures: Vec::new() }
    }

    /// Add a capture to the collection
    pub fn add(&mut self, capture: RawCapture) {
        self.captures.push(capture);
    }

    /// Get all captures
    pub fn captures(&self) -> &[RawCapture] {
        &self.captures
    }

    /// Get captures for a specific session
    pub fn get_session(&self, session_id: &str) -> Vec<&RawCapture> {
        self.captures
            .iter()
            .filter(|cap| cap.session_id == session_id)
            .collect()
    }

    /// Get list of all session IDs
    pub fn session_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.captures.iter().map(|cap| cap.session_id.clone()).collect();
        ids.sort();
        ids.dedup();
        ids
    }

    

    

    

    /// Get the number of captures in this collection
    pub fn len(&self) -> usize {
        self.captures.len()
    }

    /// Check if the collection is empty
    pub fn is_empty(&self) -> bool {
        self.captures.is_empty()
    }

    /// Get basic statistics about the collection
    pub fn statistics(&self) -> std::collections::HashMap<String, String> {
        let mut stats = std::collections::HashMap::new();

        stats.insert("total_captures".to_string(), self.captures.len().to_string());

        let session_count = self.session_ids().len();
        stats.insert("session_count".to_string(), session_count.to_string());

        if !self.captures.is_empty() {
            // Time range
            let timestamps: Vec<f64> = self.captures.iter().map(|c| c.timestamp).collect();
            if let (Some(min), Some(max)) = (
                timestamps.iter().min_by(|a, b| a.partial_cmp(b).unwrap()),
                timestamps.iter().max_by(|a, b| a.partial_cmp(b).unwrap()),
            ) {
                stats.insert("time_min".to_string(), min.to_string());
                stats.insert("time_max".to_string(), max.to_string());
                stats.insert("duration_seconds".to_string(), (max - min).to_string());
            }

            // Direction counts
            let host_to_device = self
                .captures
                .iter()
                .filter(|c| matches!(c.direction, UsbDirection::HostToDevice))
                .count();
            let device_to_host = self
                .captures
                .iter()
                .filter(|c| matches!(c.direction, UsbDirection::DeviceToHost))
                .count();
            stats.insert("host_to_device_count".to_string(), host_to_device.to_string());
            stats.insert("device_to_host_count".to_string(), device_to_host.to_string());
        }

        stats
    }
}

impl Default for CaptureCollection {
    fn default() -> Self {
        Self::new()
    }
}
