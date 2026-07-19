//! Limina / Private AI-compatible REST surface (v4), served by the presidio-rust
//! analyzer. Drop-in ISO shape for `POST /process/text`, `/ner-text`,
//! `/analyze-text`, plus `/healthz`, `/get-version`, `/metrics`, `/diagnostics`.
//!
//! Request:  `{ "text": ["…"], "link_batch": false,
//!             "entity_detection": { "accuracy": "high",
//!               "entity_types": [{"type":"ENABLE","value":["NAME"]}] },
//!             "processed_text": { "type": "MARKER" | "MASK" | "SYNTHETIC",
//!               "pattern": "[UNIQUE_NUMBERED_ENTITY_TYPE]", "mask_character": "#" } }`
//! Response: `[{ "entities": [{ "processed_text","text","best_label","labels",
//!             "location": {"stt_idx","end_idx","stt_idx_processed","end_idx_processed"} }],
//!             "entities_present", "characters_processed", "languages_detected",
//!             "processed_text" }]`

use std::collections::HashMap;
use std::sync::Arc;

use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};

use presidio_analyzer::AnalyzeOptions;

use crate::AppState;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Deserialize, Default)]
pub struct EntityTypeFilter {
    #[serde(rename = "type")]
    pub kind: String, // ENABLE | DISABLE
    #[serde(default)]
    pub value: Vec<String>,
}

#[derive(Deserialize, Default)]
pub struct EntityDetection {
    #[serde(default)]
    pub accuracy: Option<String>,
    #[serde(default)]
    pub entity_types: Vec<EntityTypeFilter>,
}

#[derive(Deserialize)]
pub struct ProcessedTextCfg {
    #[serde(rename = "type", default = "marker")]
    pub kind: String, // MARKER | MASK | SYNTHETIC
    #[serde(default)]
    pub mask_character: Option<String>,
}
fn marker() -> String {
    "MARKER".to_string()
}
impl Default for ProcessedTextCfg {
    fn default() -> Self {
        Self {
            kind: marker(),
            mask_character: None,
        }
    }
}

#[derive(Deserialize)]
pub struct ProcessTextRequest {
    pub text: Vec<String>,
    #[serde(default)]
    pub link_batch: bool,
    #[serde(default)]
    pub entity_detection: EntityDetection,
    #[serde(default)]
    pub processed_text: ProcessedTextCfg,
}

#[derive(Serialize)]
pub struct Location {
    pub stt_idx: usize,
    pub end_idx: usize,
    pub stt_idx_processed: usize,
    pub end_idx_processed: usize,
}

#[derive(Serialize)]
pub struct Entity {
    pub processed_text: String,
    pub text: String,
    pub best_label: String,
    pub labels: HashMap<String, f64>,
    pub location: Location,
}

#[derive(Serialize)]
pub struct ProcessTextItem {
    pub entities: Vec<Entity>,
    pub entities_present: bool,
    pub characters_processed: usize,
    pub languages_detected: HashMap<String, f64>,
    pub processed_text: String,
}

/// Byte offset -> character index map (Limina indices are character-based).
fn byte_to_char(text: &str) -> Vec<usize> {
    let mut m = vec![0usize; text.len() + 1];
    let mut ci = 0;
    for (bi, _) in text.char_indices() {
        m[bi] = ci;
        ci += 1;
    }
    m[text.len()] = ci;
    m
}

fn requested_entities(ed: &EntityDetection) -> Option<Vec<String>> {
    let enable: Vec<String> = ed
        .entity_types
        .iter()
        .filter(|f| f.kind.eq_ignore_ascii_case("ENABLE"))
        .flat_map(|f| f.value.clone())
        .collect();
    if enable.is_empty() {
        None
    } else {
        Some(enable)
    }
}

/// Core de-identification: analyze + build entities + redacted text (MARKER/MASK/SYNTHETIC).
fn process_one(
    state: &AppState,
    text: &str,
    ed: &EntityDetection,
    ptc: &ProcessedTextCfg,
) -> ProcessTextItem {
    let opts = AnalyzeOptions {
        entities: requested_entities(ed),
        ..Default::default()
    };
    let mut results = state.analyzer.analyze_with(text, "en", &opts);
    results.sort_by_key(|r| r.start);
    let cmap = byte_to_char(text);

    let mut entities = Vec::new();
    let mut processed = String::new();
    let mut last = 0usize;
    let mut counter: HashMap<String, usize> = HashMap::new();
    for r in &results {
        if r.start < last {
            continue; // drop overlaps (analyzer keeps highest-scoring already)
        }
        processed.push_str(&text[last..r.start]);
        let surface = &text[r.start..r.end];
        let n = counter.entry(r.entity_type.clone()).or_insert(0);
        *n += 1;
        let repl = match ptc.kind.to_uppercase().as_str() {
            "MASK" => {
                let ch = ptc
                    .mask_character
                    .clone()
                    .unwrap_or_else(|| "*".to_string());
                ch.repeat(surface.chars().count())
            }
            "SYNTHETIC" => format!("<{}>", r.entity_type),
            _ => format!("[{}_{}]", r.entity_type, n), // MARKER
        };
        let sp = processed.chars().count();
        processed.push_str(&repl);
        let ep = processed.chars().count();
        let mut labels = HashMap::new();
        labels.insert(r.entity_type.clone(), r.score);
        entities.push(Entity {
            processed_text: repl,
            text: surface.to_string(),
            best_label: r.entity_type.clone(),
            labels,
            location: Location {
                stt_idx: cmap[r.start],
                end_idx: cmap[r.end],
                stt_idx_processed: sp,
                end_idx_processed: ep,
            },
        });
        last = r.end;
    }
    processed.push_str(&text[last..]);
    ProcessTextItem {
        entities_present: !entities.is_empty(),
        characters_processed: text.chars().count(),
        languages_detected: HashMap::from([("en".to_string(), 1.0)]),
        processed_text: processed,
        entities,
    }
}

pub async fn process_text(
    State(s): State<Arc<AppState>>,
    Json(req): Json<ProcessTextRequest>,
) -> Json<Vec<ProcessTextItem>> {
    let out = req
        .text
        .iter()
        .map(|t| process_one(&s, t, &req.entity_detection, &req.processed_text))
        .collect();
    Json(out)
}

/// `/ner-text`: detection only (entities, no redacted processed_text mutation).
pub async fn ner_text(
    State(s): State<Arc<AppState>>,
    Json(req): Json<ProcessTextRequest>,
) -> Json<Vec<ProcessTextItem>> {
    let out = req
        .text
        .iter()
        .map(|t| {
            let mut item = process_one(&s, t, &req.entity_detection, &ProcessedTextCfg::default());
            item.processed_text = t.clone(); // NER = detect, don't redact
            item
        })
        .collect();
    Json(out)
}

/// `/analyze-text`: same detection surface (analysis of each entity).
pub async fn analyze_text(
    state: State<Arc<AppState>>,
    body: Json<ProcessTextRequest>,
) -> Json<Vec<ProcessTextItem>> {
    ner_text(state, body).await
}

pub async fn healthz() -> &'static str {
    "OK"
}

/// Self-served HTML API documentation.
pub async fn docs() -> axum::response::Html<&'static str> {
    axum::response::Html(include_str!("../docs/index.html"))
}

#[derive(Serialize)]
pub struct VersionInfo {
    pub app_version: String,
    pub engine: String,
}

pub async fn get_version() -> Json<VersionInfo> {
    Json(VersionInfo {
        app_version: VERSION.to_string(),
        engine: "presidio-rust".to_string(),
    })
}

pub async fn metrics() -> String {
    // Prometheus-style stub
    format!(
        "# HELP limina_up 1 if the service is up\n# TYPE limina_up gauge\nlimina_up 1\nlimina_version_info{{version=\"{VERSION}\"}} 1\n"
    )
}

pub async fn diagnostics() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "engine": "presidio-rust",
        "version": VERSION,
    }))
}
