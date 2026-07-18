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

use presidio_analyzer::{AnalyzeOptions, AnalyzerEngine};
use presidio_anonymizer::{AnonymizerEngine, OperatorConfig, RecognizerResult as AnonResult};

fn normalize_entities(entities: Option<Vec<String>>) -> Option<Vec<String>> {
    entities.map(|v| v.into_iter().map(|s| s.to_uppercase()).collect())
}

/// Map UTF-8 **byte** offsets (the analyzer's native indexing) to **character**
/// offsets, so `text[start:end]` in Python is correct on non-ASCII text — this
/// matches the offset semantics of the reference Python presidio. Returns a
/// `byte_index -> char_index` table with `text.len() + 1` entries (char-boundary
/// positions are populated; results always land on boundaries).
fn byte_to_char_map(text: &str) -> Vec<usize> {
    let mut map = vec![0usize; text.len() + 1];
    let mut ci = 0;
    for (bi, _) in text.char_indices() {
        map[bi] = ci;
        ci += 1;
    }
    map[text.len()] = ci;
    map
}

/// Detect PII entities. Returns a list of dicts with
/// `entity_type`, `start`, `end`, `score`.
#[pyfunction]
#[pyo3(signature = (text, language="en", entities=None, score_threshold=None, allow_list=None, context=None))]
#[allow(clippy::too_many_arguments)]
fn analyze<'py>(
    py: Python<'py>,
    text: &str,
    language: &str,
    entities: Option<Vec<String>>,
    score_threshold: Option<f64>,
    allow_list: Option<Vec<String>>,
    context: Option<Vec<String>>,
) -> PyResult<Bound<'py, PyList>> {
    let engine = AnalyzerEngine::new();
    let opts = AnalyzeOptions {
        entities: normalize_entities(entities),
        score_threshold,
        allow_list: allow_list.unwrap_or_default(),
        context: context.unwrap_or_default(),
        ..Default::default()
    };
    let results = engine.analyze_with(text, language, &opts);

    let cmap = byte_to_char_map(text);
    let list = PyList::empty(py);
    for r in results {
        let d = PyDict::new(py);
        d.set_item("entity_type", &r.entity_type)?;
        d.set_item("start", cmap[r.start])?;
        d.set_item("end", cmap[r.end])?;
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

/// A persistent analyzer. Builds the engine — and loads any compiled-in
/// gazetteers (names/cities/orgs, feature `gazetteers`) — **once**, then reuses
/// it across calls. The module-level [`analyze`] function rebuilds the engine
/// every call, which reloads the multi-million-entry gazetteer sets each time;
/// use this class for repeated analysis and for serving.
///
/// ```python
/// from presidio_rs import Analyzer
/// az = Analyzer()
/// az.analyze("Ada Lovelace lives in Turin", entities=["FIRST_NAME", "LOCATION"])
/// ```
#[pyclass]
struct Analyzer {
    engine: AnalyzerEngine,
}

#[pymethods]
impl Analyzer {
    #[new]
    fn new() -> Self {
        Analyzer {
            engine: AnalyzerEngine::new(),
        }
    }

    /// Detect PII. Same return shape as the module-level `analyze`.
    #[pyo3(signature = (text, language="en", entities=None, score_threshold=None, allow_list=None, context=None))]
    #[allow(clippy::too_many_arguments)]
    fn analyze<'py>(
        &self,
        py: Python<'py>,
        text: &str,
        language: &str,
        entities: Option<Vec<String>>,
        score_threshold: Option<f64>,
        allow_list: Option<Vec<String>>,
        context: Option<Vec<String>>,
    ) -> PyResult<Bound<'py, PyList>> {
        let opts = AnalyzeOptions {
            entities: normalize_entities(entities),
            score_threshold,
            allow_list: allow_list.unwrap_or_default(),
            context: context.unwrap_or_default(),
            ..Default::default()
        };
        let results = self.engine.analyze_with(text, language, &opts);
        let cmap = byte_to_char_map(text);
        let list = PyList::empty(py);
        for r in results {
            let d = PyDict::new(py);
            d.set_item("entity_type", &r.entity_type)?;
            d.set_item("start", cmap[r.start])?;
            d.set_item("end", cmap[r.end])?;
            d.set_item("score", r.score)?;
            list.append(d)?;
        }
        Ok(list)
    }

    /// Entity types this analyzer can detect for `language`.
    #[pyo3(signature = (language="en"))]
    fn supported_entities(&self, language: &str) -> Vec<String> {
        self.engine.get_supported_entities(language)
    }
}

#[pymodule]
fn presidio_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_function(wrap_pyfunction!(analyze, m)?)?;
    m.add_function(wrap_pyfunction!(anonymize, m)?)?;
    m.add_function(wrap_pyfunction!(supported_entities, m)?)?;
    m.add_class::<Analyzer>()?;
    Ok(())
}
