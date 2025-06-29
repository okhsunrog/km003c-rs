//! Example: Batch analyze multiple PD data files
//!
//! This example demonstrates how to process multiple Parquet files
//! and perform comparative analysis across different capture sessions.

use clap::Parser;
use km003c_lib::analysis::ProtocolAnalyzer;
use polars::prelude::*;
use std::collections::HashMap;
use std::error::Error;
use std::path::Path;
use tracing::{error, info};

#[derive(Parser, Debug)]
#[command(author, version, about = "Batch analyze multiple PD data files")]
struct Args {
    /// Input directory containing Parquet files
    #[arg(short, long)]
    input_dir: String,

    /// Output directory for results
    #[arg(short, long)]
    output_dir: String,

    /// File pattern to match (default: *.parquet)
    #[arg(short, long, default_value = "*.parquet")]
    pattern: String,

    /// Analysis type: summary, comparison, or all
    #[arg(short, long, default_value = "all")]
    analysis: String,

    /// Verbose logging
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    
    // Setup logging
    let log_level = if args.verbose {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };
    tracing_subscriber::fmt().with_max_level(log_level).init();

    // Create output directory
    std::fs::create_dir_all(&args.output_dir)?;
    info!("Output directory: {}", args.output_dir);

    // Find all Parquet files
    let input_path = Path::new(&args.input_dir);
    if !input_path.exists() {
        error!("Input directory does not exist: {}", args.input_dir);
        std::process::exit(1);
    }

    let mut analyzers = Vec::new();
    let mut file_paths = Vec::new();

    // Collect all matching files
    for entry in std::fs::read_dir(input_path)? {
        let entry = entry?;
        let path = entry.path();
        
        if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("parquet") {
            file_paths.push(path.clone());
        }
    }

    if file_paths.is_empty() {
        error!("No Parquet files found in: {}", args.input_dir);
        std::process::exit(1);
    }

    info!("Found {} Parquet files to analyze", file_paths.len());

    // Load all analyzers
    for file_path in &file_paths {
        match ProtocolAnalyzer::load_from_parquet(file_path) {
            Ok(analyzer) => {
                info!("Loaded {} events from: {}", analyzer.events.len(), file_path.display());
                analyzers.push(analyzer);
            }
            Err(e) => {
                error!("Failed to load {}: {}", file_path.display(), e);
            }
        }
    }

    if analyzers.is_empty() {
        error!("No analyzers loaded successfully");
        std::process::exit(1);
    }

    // Perform analysis
    match args.analysis.as_str() {
        "summary" => {
            generate_summary(&analyzers, &file_paths, &args.output_dir)?;
        }
        "comparison" => {
            generate_comparison(&analyzers, &file_paths, &args.output_dir)?;
        }
        "all" => {
            generate_summary(&analyzers, &file_paths, &args.output_dir)?;
            generate_comparison(&analyzers, &file_paths, &args.output_dir)?;
        }
        _ => {
            error!("Unknown analysis type: {}", args.analysis);
            std::process::exit(1);
        }
    }

    info!("Batch analysis complete. Results saved to: {}", args.output_dir);
    Ok(())
}

fn generate_summary(
    analyzers: &[ProtocolAnalyzer],
    file_paths: &[std::path::PathBuf],
    output_dir: &str,
) -> Result<(), Box<dyn Error>> {
    info!("=== GENERATING SUMMARY ===");
    
    let mut summary_data = Vec::new();
    
    for (i, analyzer) in analyzers.iter().enumerate() {
        let stats = analyzer.get_statistics();
        let filename = file_paths[i].file_name().unwrap().to_str().unwrap();
        
        summary_data.push(serde_json::json!({
            "filename": filename,
            "session_id": stats.get("session_id").unwrap_or(&"unknown".to_string()),
            "total_events": stats.get("total_events").unwrap_or(&"0".to_string()),
            "count_connection": stats.get("count_connection").unwrap_or(&"0".to_string()),
            "count_status": stats.get("count_status").unwrap_or(&"0".to_string()),
            "count_pd_message": stats.get("count_pd_message").unwrap_or(&"0".to_string()),
            "duration_seconds": stats.get("duration_seconds").unwrap_or(&"0".to_string()),
        }));
    }

    let json_str = serde_json::to_string(&summary_data)?;
    let df = JsonReader::new(std::io::Cursor::new(json_str)).finish()?;
    
    // Save summary
    let summary_path = format!("{}/summary.csv", output_dir);
    let file = std::fs::File::create(&summary_path)?;
    CsvWriter::new(file).finish(&mut df.clone())?;
    info!("Summary saved to: {}", summary_path);
    
    // Print summary table
    println!("=== SUMMARY ===");
    println!("{}", df);
    
    Ok(())
}

fn generate_comparison(
    analyzers: &[ProtocolAnalyzer],
    file_paths: &[std::path::PathBuf],
    output_dir: &str,
) -> Result<(), Box<dyn Error>> {
    info!("=== GENERATING COMPARISON ===");
    
    let mut comparison_data = Vec::new();
    
    for (i, analyzer) in analyzers.iter().enumerate() {
        let filename = file_paths[i].file_name().unwrap().to_str().unwrap();
        
        // Analyze patterns for this file
        if let Ok(patterns) = analyzer.analyze_packet_patterns() {
            // Convert DataFrame to a simpler format for comparison
            let event_type_col = patterns.column("event_type")?;
            let packet_type_col = patterns.column("packet_type_id")?;
            let count_col = patterns.column("count")?;
            
            for i in 0..patterns.height() {
                let event_type = event_type_col.str()?.get(i).unwrap_or("unknown");
                let packet_type_id = packet_type_col.str()?.get(i).unwrap_or("unknown");
                let count = count_col.u64()?.get(i).unwrap_or(0);
                
                comparison_data.push(serde_json::json!({
                    "filename": filename,
                    "event_type": event_type,
                    "packet_type_id": packet_type_id,
                    "count": count,
                }));
            }
        }
    }

    if comparison_data.is_empty() {
        info!("No comparison data generated");
        return Ok(());
    }

    let json_str = serde_json::to_string(&comparison_data)?;
    let df = JsonReader::new(std::io::Cursor::new(json_str)).finish()?;
    
    // For now, just save the comparison data as-is
    // TODO: Implement proper pivot functionality
    let comparison_path = format!("{}/comparison.csv", output_dir);
    let file = std::fs::File::create(&comparison_path)?;
    CsvWriter::new(file).finish(&mut df.clone())?;
    info!("Comparison saved to: {}", comparison_path);
    
    // Print comparison table
    println!("=== COMPARISON ===");
    println!("{}", df);
    
    Ok(())
} 