//! Python bindings for presidio-rust.
//!
//! Exposes a small, ergonomic surface over `presidio-analyzer` and
//! `presidio-anonymizer`. Built as an abi3 extension module named `presidio_rs`
//! via [maturin](https://www.maturin.rs/).
//!
//! ```python
//! import presidio_rs
//! presidio_rs.analyze("email me at a@b.com")
//! # [{'entity_type': 'EMAIL_ADDRESS', 'start': 12, 'end': 19, 'score': 0.5}]
//! presidio_rs.anonymize("card 4095-2609-9393-4932", operator="redact")
//! # 'card '
//! ```

use std::collections::HashMap;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use serde_json::json;

use presidio_analyzer::AnalyzerEngine;
use presidio_anonymizer::{AnonymizerEngine, OperatorConfig, RecognizerResult as AnonResult};

fn normalize_entities(entities: Option<Vec<String>>) -> Option<Vec<String>> {
    entities.map(|v| v.into_iter().map(|s| s.to_uppercase()).collect())
}

/// Detect PII entities. Returns a list of dicts with
/// `entity_type`, `start`, `end`, `score`.
#[pyfunction]
#[pyo3(signature = (text, language="en", entities=None, score_threshold=None))]
fn analyze<'py>(
    py: Python<'py>,
    text: &str,
    language: &str,
    entities: Option<Vec<String>>,
    score_threshold: Option<f64>,
) -> PyResult<Bound<'py, PyList>> {
    let engine = AnalyzerEngine::new();
    let ents = normalize_entities(entities);
    let results = engine.analyze(text, language, ents.as_deref(), score_threshold);

    let list = PyList::empty(py);
    for r in results {
        let d = PyDict::new(py);
        d.set_item("entity_type", &r.entity_type)?;
        d.set_item("start", r.start)?;
        d.set_item("end", r.end)?;
        d.set_item("score", r.score)?;
        list.append(d)?;
    }
    Ok(list)
}

/// Detect PII and return anonymized text.
///
/// `operator` is one of `replace | redact | mask | hash | keep`. `new_value`
/// customizes `replace`; `masking_char` customizes `mask`.
#[pyfunction]
#[pyo3(signature = (
    text,
    language="en",
    operator="replace",
    new_value=None,
    masking_char="*",
    entities=None,
    score_threshold=None,
))]
#[allow(clippy::too_many_arguments)]
fn anonymize(
    text: &str,
    language: &str,
    operator: &str,
    new_value: Option<String>,
    masking_char: &str,
    entities: Option<Vec<String>>,
    score_threshold: Option<f64>,
) -> PyResult<String> {
    let analyzer = AnalyzerEngine::new();
    let ents = normalize_entities(entities);
    let detected = analyzer.analyze(text, language, ents.as_deref(), score_threshold);

    let spans: Vec<AnonResult> = detected
        .iter()
        .map(|r| AnonResult::new(r.entity_type.clone(), r.start, r.end, r.score))
        .collect();

    let mut params: HashMap<String, serde_json::Value> = HashMap::new();
    match operator {
        "replace" => {
            if let Some(v) = new_value {
                params.insert("new_value".to_string(), json!(v));
            }
        }
        "mask" => {
            params.insert("masking_char".to_string(), json!(masking_char));
        }
        _ => {}
    }

    let mut operators = HashMap::new();
    operators.insert(
        "DEFAULT".to_string(),
        OperatorConfig::new(operator.to_string(), params),
    );

    let engine = AnonymizerEngine::new();
    engine
        .anonymize(text, spans, &operators)
        .map(|res| res.text)
        .map_err(|e| PyValueError::new_err(e.to_string()))
}

/// List the entity types the analyzer can detect for `language`.
#[pyfunction]
#[pyo3(signature = (language="en"))]
fn supported_entities(language: &str) -> Vec<String> {
    AnalyzerEngine::new().get_supported_entities(language)
}

#[pymodule]
fn presidio_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_function(wrap_pyfunction!(analyze, m)?)?;
    m.add_function(wrap_pyfunction!(anonymize, m)?)?;
    m.add_function(wrap_pyfunction!(supported_entities, m)?)?;
    Ok(())
}
