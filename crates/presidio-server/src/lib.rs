//! HTTP service exposing presidio-rust, mirroring Presidio's REST API shape.
//!
//! Endpoints:
//! * `GET  /health`
//! * `GET  /supportedentities?language=en`
//! * `POST /analyze`         — `{text, language?, entities?, score_threshold?, allow_list?, context?}`
//! * `POST /anonymize`       — `{text, analyzer_results:[{entity_type,start,end,score}], anonymizers:{NAME:{type,...}}}`
//! * `POST /anonymize_text`  — `{text, language?, operator?, new_value?, masking_char?}` (analyze + anonymize)

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::Value;

use presidio_analyzer::{AnalyzeOptions, AnalyzerEngine, RecognizerResult as AnalyzerResult};
use presidio_anonymizer::{
    AnonymizerEngine, EngineResult, OperatorConfig, RecognizerResult as AnonResult,
};

pub mod limina;

pub struct AppState {
    pub analyzer: AnalyzerEngine,
    pub anonymizer: AnonymizerEngine,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            analyzer: AnalyzerEngine::new(),
            anonymizer: AnonymizerEngine::new(),
        }
    }
}

/// Build the router with a fresh default state.
pub fn app() -> Router {
    app_with(Arc::new(AppState::default()))
}

/// Build the router with a shared state (useful for tests).
pub fn app_with(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/supportedentities", get(supported_entities))
        .route("/analyze", post(analyze))
        .route("/anonymize", post(anonymize))
        .route("/anonymize_text", post(anonymize_text))
        // Limina / Private AI-compatible (v4) surface
        .route("/process/text", post(limina::process_text))
        .route("/ner/text", post(limina::ner_text))
        .route("/analyze/text", post(limina::analyze_text))
        .route("/healthz", get(limina::healthz))
        .route("/get-version", get(limina::get_version))
        .route("/metrics", get(limina::metrics))
        .route("/diagnostics", get(limina::diagnostics))
        .route("/docs", get(limina::docs))
        .route("/", get(limina::docs))
        .with_state(state)
}

fn default_lang() -> String {
    "en".to_string()
}

async fn health() -> &'static str {
    "ok"
}

#[derive(Deserialize)]
struct LangQuery {
    #[serde(default = "default_lang")]
    language: String,
}

async fn supported_entities(
    State(s): State<Arc<AppState>>,
    Query(q): Query<LangQuery>,
) -> Json<Vec<String>> {
    Json(s.analyzer.get_supported_entities(&q.language))
}

#[derive(Deserialize)]
struct AnalyzeRequest {
    text: String,
    #[serde(default = "default_lang")]
    language: String,
    entities: Option<Vec<String>>,
    score_threshold: Option<f64>,
    #[serde(default)]
    allow_list: Vec<String>,
    #[serde(default)]
    context: Vec<String>,
}

async fn analyze(
    State(s): State<Arc<AppState>>,
    Json(req): Json<AnalyzeRequest>,
) -> Json<Vec<AnalyzerResult>> {
    let opts = AnalyzeOptions {
        entities: req.entities,
        score_threshold: req.score_threshold,
        allow_list: req.allow_list,
        context: req.context,
        ..Default::default()
    };
    Json(s.analyzer.analyze_with(&req.text, &req.language, &opts))
}

#[derive(Deserialize)]
struct AnalyzerResultDto {
    entity_type: String,
    start: usize,
    end: usize,
    #[serde(default)]
    score: f64,
}

#[derive(Deserialize)]
struct AnonymizeRequest {
    text: String,
    #[serde(default)]
    analyzer_results: Vec<AnalyzerResultDto>,
    #[serde(default)]
    anonymizers: HashMap<String, Value>,
}

/// Convert Presidio-style `{"NAME": {"type": "op", ...params}}` into operator configs.
pub fn build_operators(anonymizers: &HashMap<String, Value>) -> HashMap<String, OperatorConfig> {
    let mut out = HashMap::new();
    for (name, v) in anonymizers {
        let Some(obj) = v.as_object() else { continue };
        let op_name = obj
            .get("type")
            .and_then(|t| t.as_str())
            .unwrap_or("replace")
            .to_string();
        let params: HashMap<String, Value> = obj
            .iter()
            .filter(|(k, _)| k.as_str() != "type")
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        out.insert(name.clone(), OperatorConfig::new(op_name, params));
    }
    out
}

async fn anonymize(
    State(s): State<Arc<AppState>>,
    Json(req): Json<AnonymizeRequest>,
) -> Result<Json<EngineResult>, (StatusCode, String)> {
    let spans: Vec<AnonResult> = req
        .analyzer_results
        .iter()
        .map(|r| AnonResult::new(r.entity_type.clone(), r.start, r.end, r.score))
        .collect();
    let operators = build_operators(&req.anonymizers);
    s.anonymizer
        .anonymize(&req.text, spans, &operators)
        .map(Json)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))
}

#[derive(Deserialize)]
struct AnonymizeTextRequest {
    text: String,
    #[serde(default = "default_lang")]
    language: String,
    #[serde(default = "default_operator")]
    operator: String,
    new_value: Option<String>,
    masking_char: Option<String>,
}

fn default_operator() -> String {
    "replace".to_string()
}

async fn anonymize_text(
    State(s): State<Arc<AppState>>,
    Json(req): Json<AnonymizeTextRequest>,
) -> Result<Json<EngineResult>, (StatusCode, String)> {
    let detected = s.analyzer.analyze(&req.text, &req.language, None, None);
    let spans: Vec<AnonResult> = detected
        .iter()
        .map(|r| AnonResult::new(r.entity_type.clone(), r.start, r.end, r.score))
        .collect();

    let mut params: HashMap<String, Value> = HashMap::new();
    match req.operator.as_str() {
        "replace" => {
            if let Some(v) = &req.new_value {
                params.insert("new_value".to_string(), Value::String(v.clone()));
            }
        }
        "mask" => {
            let mc = req.masking_char.clone().unwrap_or_else(|| "*".to_string());
            params.insert("masking_char".to_string(), Value::String(mc));
        }
        _ => {}
    }
    let mut operators = HashMap::new();
    operators.insert(
        "DEFAULT".to_string(),
        OperatorConfig::new(req.operator, params),
    );

    s.anonymizer
        .anonymize(&req.text, spans, &operators)
        .map(Json)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn build_operators_maps_type_and_params() {
        let mut input = HashMap::new();
        input.insert(
            "DEFAULT".to_string(),
            serde_json::json!({"type": "mask", "masking_char": "#"}),
        );
        let ops = build_operators(&input);
        let cfg = ops.get("DEFAULT").unwrap();
        assert_eq!(cfg.operator_name, "mask");
        assert!(cfg.params.contains_key("masking_char"));
        assert!(!cfg.params.contains_key("type"));
    }
}
