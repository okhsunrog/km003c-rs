//! Protocol analysis and data processing utilities for KM003C reverse engineering.
//!
//! This module provides tools for collecting, processing, and analyzing protocol data
//! using Polars DataFrames and Parquet storage for efficient data handling.

use crate::pd::EventPacket;
use polars::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tracing::{debug, info, warn};

/// Represents a single event with metadata for analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyzedEvent {
    /// Timestamp in seconds since epoch
    pub timestamp: f64,
    /// Event type as string
    pub event_type: String,
    /// Raw packet type ID
    pub packet_type_id: Option<u8>,
    /// Connection event details
    pub connection_action: Option<String>,
    pub connection_cc_pin: Option<u8>,
    /// Status packet readings
    pub vbus_raw: Option<u16>,
    pub ibus_raw: Option<u16>,
    pub cc1_raw: Option<u16>,
    pub cc2_raw: Option<u16>,
    /// PD message details
    pub pd_direction: Option<String>,
    pub pd_message_type: Option<String>,
    pub pd_source_caps_count: Option<u8>,
    /// Raw hex data for further analysis
    pub raw_hex: String,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl AnalyzedEvent {
    /// Convert an EventPacket to an AnalyzedEvent
    pub fn from_event_packet(event: &EventPacket, timestamp: f64, raw_hex: String) -> Self {
        let mut analyzed = AnalyzedEvent {
            timestamp,
            event_type: String::new(),
            packet_type_id: None,
            connection_action: None,
            connection_cc_pin: None,
            vbus_raw: None,
            ibus_raw: None,
            cc1_raw: None,
            cc2_raw: None,
            pd_direction: None,
            pd_message_type: None,
            pd_source_caps_count: None,
            raw_hex,
            metadata: HashMap::new(),
        };

        match event {
            EventPacket::Connection(conn) => {
                analyzed.event_type = "connection".to_string();
                analyzed.packet_type_id = Some(conn.type_id);
                analyzed.connection_action = Some(match conn.action() {
                    1 => "attach".to_string(),
                    2 => "detach".to_string(),
                    _ => format!("unknown_{}", conn.action()),
                });
                analyzed.connection_cc_pin = Some(conn.cc_pin());
            }
            EventPacket::Status(status) => {
                analyzed.event_type = "status".to_string();
                analyzed.packet_type_id = Some(status.type_id);
                analyzed.vbus_raw = Some(status.vbus_raw.get());
                analyzed.ibus_raw = Some(status.ibus_raw.get());
                analyzed.cc1_raw = Some(status.cc1_raw.get());
                analyzed.cc2_raw = Some(status.cc2_raw.get());
            }
            EventPacket::PdMessage(pd) => {
                analyzed.event_type = "pd_message".to_string();
                analyzed.pd_direction = Some(if pd.is_src_to_snk { "src_to_snk".to_string() } else { "snk_to_src".to_string() });
                
                // Try to parse the PD message for more details
                if let Ok(msg) = pd.parse_message_stateless() {
                    analyzed.pd_message_type = Some(format!("{:?}", msg.header.message_type()));
                    
                    // Extract source capabilities count if available
                    if let Some(usbpd::protocol_layer::message::Data::SourceCapabilities(caps)) = &msg.data {
                        analyzed.pd_source_caps_count = Some(caps.pdos().len() as u8);
                    }
                }
            }
        }

        analyzed
    }
}

/// Protocol analyzer for collecting and processing KM003C data
pub struct ProtocolAnalyzer {
    pub events: Vec<AnalyzedEvent>,
    session_id: String,
}

impl ProtocolAnalyzer {
    /// Create a new protocol analyzer
    pub fn new(session_id: Option<String>) -> Self {
        let session_id = session_id.unwrap_or_else(|| {
            use std::time::{SystemTime, UNIX_EPOCH};
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
            format!("session_{}", now.as_secs())
        });

        Self {
            events: Vec::new(),
            session_id,
        }
    }

    /// Add events from a raw data stream
    pub fn add_events(&mut self, raw_data: &[u8], timestamp: f64) -> Result<(), crate::error::KMError> {
        let raw_hex = hex::encode(raw_data);
        
        match crate::pd::parse_event_stream(raw_data) {
            Ok(events) => {
                let event_count = events.len();
                for event in &events {
                    let analyzed = AnalyzedEvent::from_event_packet(event, timestamp, raw_hex.clone());
                    self.events.push(analyzed);
                }
                debug!("Added {} events from stream", event_count);
            }
            Err(e) => {
                warn!("Failed to parse event stream: {:?}", e);
                // Still add a record for the failed parse
                let failed_event = AnalyzedEvent {
                    timestamp,
                    event_type: "parse_error".to_string(),
                    raw_hex,
                    metadata: {
                        let mut map = HashMap::new();
                        map.insert("error".to_string(), format!("{:?}", e));
                        map
                    },
                    ..Default::default()
                };
                self.events.push(failed_event);
            }
        }
        Ok(())
    }

    /// Convert events to a Polars DataFrame
    pub fn to_dataframe(&self) -> Result<DataFrame, PolarsError> {
        if self.events.is_empty() {
            return Err(PolarsError::NoData("No events to convert".into()));
        }

        // Convert to DataFrame using serde
        let json_str = serde_json::to_string(&self.events)
            .map_err(|e| PolarsError::ComputeError(format!("Serialization error: {}", e).into()))?;
        
        let df = JsonReader::new(std::io::Cursor::new(json_str))
            .finish()
            .map_err(|e| PolarsError::ComputeError(format!("JSON parsing error: {}", e).into()))?;

        Ok(df)
    }

    /// Save events to a Parquet file
    pub fn save_to_parquet<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn std::error::Error>> {
        let df = self.to_dataframe()?;
        
        let file = std::fs::File::create(path.as_ref())?;
        ParquetWriter::new(file)
            .finish(&mut df.clone())
            .map_err(|e| format!("Parquet write error: {}", e))?;
        
        info!("Saved {} events to {:?}", self.events.len(), path.as_ref());
        Ok(())
    }

    /// Load events from a Parquet file
    pub fn load_from_parquet<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let file = std::fs::File::open(path.as_ref())?;
        let df = ParquetReader::new(file)
            .finish()
            .map_err(|e| format!("Parquet read error: {}", e))?;

        // For now, we'll create a simple analyzer with basic info
        // Full deserialization would require more complex logic
        let session_id = path.as_ref()
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("loaded_session")
            .to_string();

        info!("Loaded DataFrame with {} rows from {:?}", df.shape().0, path.as_ref());
        
        // Return analyzer with empty events for now
        // TODO: Implement proper DataFrame to AnalyzedEvent conversion
        Ok(Self {
            events: Vec::new(),
            session_id,
        })
    }

    /// Get basic statistics about the collected data
    pub fn get_statistics(&self) -> HashMap<String, String> {
        let mut stats = HashMap::new();
        
        stats.insert("total_events".to_string(), self.events.len().to_string());
        stats.insert("session_id".to_string(), self.session_id.clone());
        
        if !self.events.is_empty() {
            let event_types: HashMap<String, usize> = self.events
                .iter()
                .fold(HashMap::new(), |mut acc, event| {
                    *acc.entry(event.event_type.clone()).or_insert(0) += 1;
                    acc
                });
            
            for (event_type, count) in event_types {
                stats.insert(format!("count_{}", event_type), count.to_string());
            }
            
            // Time range
            let timestamps: Vec<f64> = self.events.iter().map(|e| e.timestamp).collect();
            if let (Some(min), Some(max)) = (timestamps.iter().min_by(|a, b| a.partial_cmp(b).unwrap()), 
                                           timestamps.iter().max_by(|a, b| a.partial_cmp(b).unwrap())) {
                stats.insert("time_min".to_string(), min.to_string());
                stats.insert("time_max".to_string(), max.to_string());
                stats.insert("duration_seconds".to_string(), (max - min).to_string());
            }
        }
        
        stats
    }

    /// Analyze packet type patterns
    pub fn analyze_packet_patterns(&self) -> Result<DataFrame, PolarsError> {
        let df = self.to_dataframe()?;
        
        // Group by packet type and analyze patterns
        let patterns = df.lazy()
            .group_by(["event_type", "packet_type_id"])
            .agg([
                col("*").count().alias("count"),
                col("timestamp").mean().alias("avg_timestamp"),
                col("timestamp").std(1).alias("std_timestamp"),
            ])
            .collect()?;
        
        Ok(patterns)
    }

    /// Find potential protocol sequences
    pub fn find_sequences(&self, window_size: usize) -> Result<DataFrame, PolarsError> {
        let df = self.to_dataframe()?;
        
        if df.height() < window_size {
            return Err(PolarsError::NoData("Not enough data for sequence analysis".into()));
        }

        // Create sliding windows of events
        let mut sequences = Vec::new();
        for window in self.events.windows(window_size) {
            let sequence: Vec<String> = window.iter().map(|e| e.event_type.clone()).collect();
            let start_time = window[0].timestamp;
            let end_time = window[window_size - 1].timestamp;
            
            sequences.push(serde_json::json!({
                "sequence": sequence.join("->"),
                "start_time": start_time,
                "end_time": end_time,
                "duration": end_time - start_time,
            }));
        }

        let json_str = serde_json::to_string(&sequences)
            .map_err(|e| PolarsError::ComputeError(format!("Serialization error: {}", e).into()))?;
        
        let df = JsonReader::new(std::io::Cursor::new(json_str))
            .finish()
            .map_err(|e| PolarsError::ComputeError(format!("JSON parsing error: {}", e).into()))?;

        Ok(df)
    }

    /// Merge another analyzer's events into this one
    pub fn merge(&mut self, mut other: ProtocolAnalyzer) {
        let other_count = other.event_count();
        let other_session = other.session_id().to_string();
        
        // Move events from other to self
        self.events.append(&mut other.events);
        
        info!("Merged {} events from '{}' into '{}' (total: {})", 
              other_count, other_session, self.session_id(), self.event_count());
    }

    /// Get the number of events in this analyzer
    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    /// Get a reference to the session ID
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Drain all events from this analyzer (consumes the analyzer)
    pub fn drain_events(&mut self) -> Vec<AnalyzedEvent> {
        std::mem::take(&mut self.events)
    }
}

impl Default for AnalyzedEvent {
    fn default() -> Self {
        Self {
            timestamp: 0.0,
            event_type: String::new(),
            packet_type_id: None,
            connection_action: None,
            connection_cc_pin: None,
            vbus_raw: None,
            ibus_raw: None,
            cc1_raw: None,
            cc2_raw: None,
            pd_direction: None,
            pd_message_type: None,
            pd_source_caps_count: None,
            raw_hex: String::new(),
            metadata: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pd::{ConnectionEvent, StatusPacket};

    #[test]
    fn test_analyzed_event_from_connection() {
        let conn_event = ConnectionEvent {
            type_id: 0x45,
            timestamp_bytes: [0x01, 0x02, 0x03],
            _reserved: 0,
            event_data: 0x12, // CC1, Attach
        };
        
        let event = EventPacket::Connection(conn_event);
        let analyzed = AnalyzedEvent::from_event_packet(&event, 123.456, "450102030012".to_string());
        
        assert_eq!(analyzed.event_type, "connection");
        assert_eq!(analyzed.packet_type_id, Some(0x45));
        assert_eq!(analyzed.connection_action, Some("attach".to_string()));
        assert_eq!(analyzed.connection_cc_pin, Some(1));
    }

    #[test]
    fn test_protocol_analyzer_basic() {
        let mut analyzer = ProtocolAnalyzer::new(None);
        assert_eq!(analyzer.events.len(), 0);
        
        let stats = analyzer.get_statistics();
        assert_eq!(stats.get("total_events").unwrap(), "0");
    }
} 