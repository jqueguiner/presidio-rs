//! `presidio` — a small CLI over presidio-analyzer + presidio-anonymizer.
//!
//! ```text
//! presidio analyze   --text "call me at 212-555-0143"
//! presidio anonymize --text "my ssn is 078-05-1120" --operator mask
//! ```

use std::collections::HashMap;

use anyhow::Result;
use clap::{Parser, Subcommand};
use presidio_analyzer::AnalyzerEngine;
use presidio_anonymizer::{AnonymizerEngine, OperatorConfig, RecognizerResult as AnonResult};
use serde_json::{json, Value};

#[derive(Parser)]
#[command(
    name = "presidio",
    version,
    about = "PII detection & anonymization (Rust port of Presidio)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Detect PII entities and print them as JSON.
    Analyze(AnalyzeArgs),
    /// Detect PII and return anonymized text.
    Anonymize(AnonymizeArgs),
    /// List the entity types the analyzer can detect.
    Entities,
}

#[derive(Parser)]
struct AnalyzeArgs {
    #[arg(long)]
    text: String,
    #[arg(long, default_value = "en")]
    language: String,
    /// Restrict to a comma-separated list of entity types.
    #[arg(long)]
    entities: Option<String>,
    /// Drop results below this score.
    #[arg(long)]
    min_score: Option<f64>,
}

#[derive(Parser)]
struct AnonymizeArgs {
    #[arg(long)]
    text: String,
    #[arg(long, default_value = "en")]
    language: String,
    #[arg(long)]
    entities: Option<String>,
    #[arg(long)]
    min_score: Option<f64>,
    /// Operator to apply: replace | redact | mask | hash | keep.
    #[arg(long, default_value = "replace")]
    operator: String,
    /// `new_value` for `replace`.
    #[arg(long)]
    new_value: Option<String>,
    /// `masking_char` for `mask`.
    #[arg(long, default_value = "*")]
    masking_char: String,
}

fn parse_entities(s: &Option<String>) -> Option<Vec<String>> {
    s.as_ref().map(|s| {
        s.split(',')
            .map(|e| e.trim().to_uppercase())
            .filter(|e| !e.is_empty())
            .collect()
    })
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Analyze(args) => run_analyze(args),
        Command::Anonymize(args) => run_anonymize(args),
        Command::Entities => {
            let engine = AnalyzerEngine::new();
            for e in engine.get_supported_entities("en") {
                println!("{e}");
            }
            Ok(())
        }
    }
}

fn run_analyze(args: AnalyzeArgs) -> Result<()> {
    let engine = AnalyzerEngine::new();
    let entities = parse_entities(&args.entities);
    let results = engine.analyze(
        &args.text,
        &args.language,
        entities.as_deref(),
        args.min_score,
    );
    println!("{}", serde_json::to_string_pretty(&results)?);
    Ok(())
}

fn run_anonymize(args: AnonymizeArgs) -> Result<()> {
    let analyzer = AnalyzerEngine::new();
    let entities = parse_entities(&args.entities);
    let detected = analyzer.analyze(
        &args.text,
        &args.language,
        entities.as_deref(),
        args.min_score,
    );

    // Map analyzer results onto the anonymizer's own result type.
    let anon_results: Vec<AnonResult> = detected
        .iter()
        .map(|r| AnonResult::new(r.entity_type.clone(), r.start, r.end, r.score))
        .collect();

    // Build the operator config from CLI flags, applied to every entity via DEFAULT.
    let mut params: HashMap<String, Value> = HashMap::new();
    match args.operator.as_str() {
        "replace" => {
            if let Some(v) = &args.new_value {
                params.insert("new_value".to_string(), json!(v));
            }
        }
        "mask" => {
            params.insert("masking_char".to_string(), json!(args.masking_char));
            params.insert("from_end".to_string(), json!(false));
        }
        _ => {}
    }

    let mut operators: HashMap<String, OperatorConfig> = HashMap::new();
    operators.insert(
        "DEFAULT".to_string(),
        OperatorConfig::new(args.operator.clone(), params),
    );

    let anonymizer = AnonymizerEngine::new();
    let result = anonymizer.anonymize(&args.text, anon_results, &operators)?;
    println!("{}", result.text);
    eprintln!(
        "{}",
        serde_json::to_string_pretty(&json!({ "items": result.items }))?
    );
    Ok(())
}
