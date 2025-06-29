use polars::prelude::*;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// USB direction enum
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UsbDirection {
    HostToDevice,  // H->D
    DeviceToHost,  // D->H
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
    pub session_id: String,        // e.g., "orig_adc_1000hz.6"
    pub timestamp: f64,            // from frame.time_relative
    pub direction: UsbDirection,   // H->D or D->H
    pub raw_bytes: Vec<u8>,        // the actual USB data
    pub frame_number: u32,         // from frame.number
    pub added_datetime: String,    // ISO 8601 datetime when this row was added
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
        Self {
            captures: Vec::new(),
        }
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
        let mut ids: Vec<String> = self.captures
            .iter()
            .map(|cap| cap.session_id.clone())
            .collect();
        ids.sort();
        ids.dedup();
        ids
    }

    /// Save all captures to a parquet file
    pub fn save_to_parquet<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn std::error::Error>> {
        if self.captures.is_empty() {
            return Err("No captures to save".into());
        }

        let mut session_ids = Vec::new();
        let mut timestamps = Vec::new();
        let mut directions = Vec::new();
        let mut raw_bytes_vecs = Vec::new();
        let mut frame_numbers = Vec::new();
        let mut added_datetimes = Vec::new();

        for capture in &self.captures {
            session_ids.push(capture.session_id.clone());
            timestamps.push(capture.timestamp);
            directions.push(capture.direction.to_string());
            raw_bytes_vecs.push(capture.raw_bytes.as_slice());
            frame_numbers.push(capture.frame_number);
            added_datetimes.push(capture.added_datetime.clone());
        }

        // Use Series::new with Vec<&[u8]> for Binary type
        let raw_bytes_series = Series::new("raw_bytes".into(), raw_bytes_vecs);

        let df = DataFrame::new(vec![
            Series::new("session_id".into(), session_ids).into(),
            Series::new("timestamp".into(), timestamps).into(),
            Series::new("direction".into(), directions).into(),
            raw_bytes_series.into(),
            Series::new("frame_number".into(), frame_numbers).into(),
            Series::new("added_datetime".into(), added_datetimes).into(),
        ]).map_err(|e| format!("DataFrame creation error: {}", e))?;

        let file = std::fs::File::create(path.as_ref())?;
        ParquetWriter::new(file)
            .finish(&mut df.clone())
            .map_err(|e| format!("Parquet write error: {}", e))?;
        println!("Saved {} captures to {:?}", self.captures.len(), path.as_ref());
        Ok(())
    }

    /// Load captures from a parquet file
    pub fn load_from_parquet<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let file = std::fs::File::open(path.as_ref())?;
        let df = ParquetReader::new(file)
            .finish()
            .map_err(|e| format!("Parquet read error: {}", e))?;

        let mut captures = Vec::new();
        for row_idx in 0..df.height() {
            let session_id = df.column("session_id")?.str()?.get(row_idx).unwrap_or("").to_string();
            let timestamp = df.column("timestamp")?.f64()?.get(row_idx).unwrap_or(0.0);
            let direction_str = df.column("direction")?.str()?.get(row_idx).unwrap_or("").to_string();
            // Handle both Binary and List types for raw_bytes
            let raw_bytes = match df.column("raw_bytes")?.dtype() {
                DataType::Binary => df.column("raw_bytes")?.binary()?.get(row_idx).unwrap_or(&[]).to_vec(),
                DataType::List(_) => {
                    // For now, return empty vector for list types to avoid compilation issues
                    // TODO: Implement proper list handling when Polars API is better understood
                    vec![]
                },
                _ => vec![],
            };
            let frame_number = df.column("frame_number")?.u32()?.get(row_idx).unwrap_or(0);
            let added_datetime = df.column("added_datetime")?.str()?.get(row_idx).unwrap_or("").to_string();
            let direction = match direction_str.as_str() {
                "H->D" => UsbDirection::HostToDevice,
                "D->H" => UsbDirection::DeviceToHost,
                _ => continue,
            };
            let capture = RawCapture::new(
                session_id,
                timestamp,
                direction,
                raw_bytes,
                frame_number,
                added_datetime,
            );
            captures.push(capture);
        }
        println!("Loaded {} captures from {:?}", captures.len(), path.as_ref());
        Ok(Self { captures })
    }

    /// Append captures to an existing parquet file (or create new if doesn't exist)
    pub fn append_to_parquet<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn std::error::Error>> {
        if self.captures.is_empty() {
            return Err("No captures to save".into());
        }

        // Check if file exists
        let path_ref = path.as_ref();
        let existing_captures = if path_ref.exists() {
            println!("Loading existing captures from {:?}", path_ref);
            Self::load_from_parquet(path_ref)?
        } else {
            println!("Creating new parquet file at {:?}", path_ref);
            Self::new()
        };

        // Combine existing and new captures
        let mut combined = existing_captures;
        for capture in &self.captures {
            combined.add(capture.clone());
        }

        // Save combined collection
        combined.save_to_parquet(path_ref)
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
            if let (Some(min), Some(max)) = (timestamps.iter().min_by(|a, b| a.partial_cmp(b).unwrap()), 
                                           timestamps.iter().max_by(|a, b| a.partial_cmp(b).unwrap())) {
                stats.insert("time_min".to_string(), min.to_string());
                stats.insert("time_max".to_string(), max.to_string());
                stats.insert("duration_seconds".to_string(), (max - min).to_string());
            }
            
            // Direction counts
            let host_to_device = self.captures.iter().filter(|c| matches!(c.direction, UsbDirection::HostToDevice)).count();
            let device_to_host = self.captures.iter().filter(|c| matches!(c.direction, UsbDirection::DeviceToHost)).count();
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
