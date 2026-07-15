//! The orchestrator: runs the NLP pipeline, every relevant recognizer, context
//! enhancement, thresholding and conflict resolution.
//!
//! Port of `presidio_analyzer.AnalyzerEngine`.

use std::cmp::Ordering;

use crate::context::LemmaContextAwareEnhancer;
use crate::entities::RecognizerResult;
use crate::nlp::{NlpEngine, SimpleNlpEngine};
use crate::registry::RecognizerRegistry;

pub struct AnalyzerEngine {
    pub registry: RecognizerRegistry,
    pub nlp_engine: Box<dyn NlpEngine>,
    pub context_enhancer: LemmaContextAwareEnhancer,
    pub default_score_threshold: f64,
    pub supported_language: String,
}

impl Default for AnalyzerEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl AnalyzerEngine {
    /// Engine with all predefined English recognizers and the default NLP engine.
    pub fn new() -> Self {
        Self {
            registry: RecognizerRegistry::with_predefined("en"),
            nlp_engine: Box::new(SimpleNlpEngine::new()),
            context_enhancer: LemmaContextAwareEnhancer::default(),
            default_score_threshold: 0.0,
            supported_language: "en".to_string(),
        }
    }

    pub fn with_registry(mut self, registry: RecognizerRegistry) -> Self {
        self.registry = registry;
        self
    }

    pub fn with_nlp_engine(mut self, engine: Box<dyn NlpEngine>) -> Self {
        self.nlp_engine = engine;
        self
    }

    pub fn get_supported_entities(&self, language: &str) -> Vec<String> {
        self.registry.supported_entities(language)
    }

    /// Detect PII in `text`.
    ///
    /// * `entities` — restrict detection to these entity types (`None` = all)
    /// * `score_threshold` — drop results scoring below this (`None` = engine default)
    pub fn analyze(
        &self,
        text: &str,
        language: &str,
        entities: Option<&[String]>,
        score_threshold: Option<f64>,
    ) -> Vec<RecognizerResult> {
        let all_entities = self.registry.supported_entities(language);
        let requested: Vec<String> = match entities {
            Some(e) => e.to_vec(),
            None => all_entities,
        };

        let nlp = self.nlp_engine.process(text, language);

        let mut results: Vec<RecognizerResult> = Vec::new();
        for recognizer in self.registry.get_recognizers(language, &requested) {
            // Restrict each recognizer to the intersection of what it and the
            // caller want.
            let rec_entities: Vec<String> = recognizer
                .supported_entities()
                .into_iter()
                .filter(|e| requested.iter().any(|r| r == e))
                .collect();
            if rec_entities.is_empty() {
                continue;
            }
            results.extend(recognizer.analyze(text, &rec_entities, Some(&nlp)));
        }

        self.context_enhancer.enhance(&mut results, &nlp);

        let threshold = score_threshold.unwrap_or(self.default_score_threshold);
        results.retain(|r| r.score >= threshold);

        let mut results = remove_conflicts(results);
        results.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));
        results
    }
}

/// Keep the highest-scoring, non-overlapping set of results across recognizers.
/// Ties broken by longer span. Mirrors the intent of Presidio's
/// `_remove_conflicts` (favor higher score, then wider coverage).
fn remove_conflicts(mut results: Vec<RecognizerResult>) -> Vec<RecognizerResult> {
    results.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(Ordering::Equal)
            .then_with(|| b.len().cmp(&a.len()))
            .then_with(|| a.start.cmp(&b.start))
    });

    let mut kept: Vec<RecognizerResult> = Vec::new();
    for r in results {
        if kept.iter().any(|k| k.intersects(&r)) {
            continue;
        }
        kept.push(r);
    }
    kept
}
