//! Example: Analyze PD data from Parquet files
//!
//! This example demonstrates how to load and analyze PD data that was
//! previously collected and saved to Parquet files.

use clap::Parser;
use km003c_lib::analysis::ProtocolAnalyzer;
use polars::prelude::*;
use std::error::Error;
use tracing::{error, info};

#[derive(Parser, Debug)]
#[command(author, version, about = "Analyze PD data from Parquet files")]
struct Args {
    /// Input Parquet file path
    #[arg(short, long)]
    input: String,

    /// Analysis type: stats, patterns, sequences, or all
    #[arg(short, long, default_value = "all")]
    analysis: String,

    /// Sequence window size for sequence analysis
    #[arg(short, long, default_value = "3")]
    window_size: usize,

    /// Output format: table, csv, json
    #[arg(short, long, default_value = "table")]
    format: String,

    /// Output file for results (optional)
    #[arg(short, long)]
    output: Option<String>,

    /// Filter by event type (e.g., "pd_message", "connection", "status")
    #[arg(short, long)]
    event_type: Option<String>,

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

    info!("Loading data from: {}", args.input);
    
    // Load the analyzer from Parquet file
    let analyzer = ProtocolAnalyzer::load_from_parquet(&args.input)?;
    info!("Loaded {} events from session: {}", analyzer.events.len(), analyzer.session_id());

    // Print basic statistics
    let stats = analyzer.get_statistics();
    info!("Dataset Statistics:");
    for (key, value) in &stats {
        info!("  {}: {}", key, value);
    }

    // Perform requested analysis
    match args.analysis.as_str() {
        "stats" => {
            print_statistics(&stats, &args.format, &args.output)?;
        }
        "patterns" => {
            analyze_patterns(&analyzer, &args.format, &args.output, &args.event_type)?;
        }
        "sequences" => {
            analyze_sequences(&analyzer, args.window_size, &args.format, &args.output)?;
        }
        "all" => {
            print_statistics(&stats, &args.format, &args.output)?;
            analyze_patterns(&analyzer, &args.format, &args.output, &args.event_type)?;
            analyze_sequences(&analyzer, args.window_size, &args.format, &args.output)?;
        }
        _ => {
            error!("Unknown analysis type: {}", args.analysis);
            std::process::exit(1);
        }
    }

    Ok(())
}

fn print_statistics(
    stats: &std::collections::HashMap<String, String>,
    format: &str,
    output: &Option<String>,
) -> Result<(), Box<dyn Error>> {
    info!("=== STATISTICS ===");
    
    let mut df_data = Vec::new();
    for (key, value) in stats {
        df_data.push(serde_json::json!({
            "metric": key,
            "value": value
        }));
    }

    let json_str = serde_json::to_string(&df_data)?;
    let df = JsonReader::new(std::io::Cursor::new(json_str)).finish()?;
    
    print_dataframe(&df, format, output, "statistics")?;
    Ok(())
}

fn analyze_patterns(
    analyzer: &ProtocolAnalyzer,
    format: &str,
    output: &Option<String>,
    event_type_filter: &Option<String>,
) -> Result<(), Box<dyn Error>> {
    info!("=== PACKET PATTERNS ===");
    
    let patterns = analyzer.analyze_packet_patterns()?;
    
    // Apply event type filter if specified
    let filtered_patterns = if let Some(filter_type) = event_type_filter {
        patterns.lazy()
            .filter(col("event_type").eq(lit(filter_type.as_str())))
            .collect()?
    } else {
        patterns
    };
    
    print_dataframe(&filtered_patterns, format, output, "patterns")?;
    Ok(())
}

fn analyze_sequences(
    analyzer: &ProtocolAnalyzer,
    window_size: usize,
    format: &str,
    output: &Option<String>,
) -> Result<(), Box<dyn Error>> {
    info!("=== EVENT SEQUENCES (window size: {}) ===", window_size);
    
    let sequences = analyzer.find_sequences(window_size)?;
    
    // Group by sequence and count occurrences
    let sequence_counts = sequences.lazy()
        .group_by(["sequence"])
        .agg([
            col("*").count().alias("occurrences"),
            col("duration").mean().alias("avg_duration"),
            col("duration").std(1).alias("std_duration"),
        ])
        .sort(["occurrences"], Default::default())
        .collect()?;
    
    print_dataframe(&sequence_counts, format, output, "sequences")?;
    Ok(())
}

fn print_dataframe(
    df: &DataFrame,
    format: &str,
    output: &Option<String>,
    analysis_type: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    match format {
        "table" => {
            println!("{}", df);
        }
        "csv" => {
            let mut buffer = Vec::new();
            let mut df_clone = df.clone();
            CsvWriter::new(&mut buffer).finish(&mut df_clone)?;
            let csv_data = String::from_utf8(buffer)?;
            if let Some(output_path) = output {
                let filename = format!("{}_{}.csv", output_path, analysis_type);
                std::fs::write(&filename, csv_data)?;
                info!("Saved CSV to: {}", filename);
            } else {
                println!("{}", csv_data);
            }
        }
        "json" => {
            let json_data = serde_json::to_string_pretty(df)?;
            if let Some(output_path) = output {
                let filename = format!("{}_{}.json", output_path, analysis_type);
                std::fs::write(&filename, json_data)?;
                info!("Saved JSON to: {}", filename);
            } else {
                println!("{}", json_data);
            }
        }
        _ => {
            error!("Unknown output format: {}", format);
            std::process::exit(1);
        }
    }
    Ok(())
} 