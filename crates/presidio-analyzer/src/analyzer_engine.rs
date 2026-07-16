//! The orchestrator: runs the NLP pipeline, every relevant recognizer, context
//! enhancement, thresholding and conflict resolution.
//!
//! Port of `presidio_analyzer.AnalyzerEngine`.

use std::cmp::Ordering;

use regex::Regex;

use crate::context::LemmaContextAwareEnhancer;
use crate::entities::RecognizerResult;
use crate::nlp::{NlpEngine, SimpleNlpEngine};
use crate::recognizer::EntityRecognizer;
use crate::registry::RecognizerRegistry;

/// How `allow_list` entries are matched against detected entity text.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum AllowListMatch {
    /// Case-insensitive exact string match (default).
    #[default]
    Exact,
    /// Each allow-list entry is a regex; a result is dropped if its text fully
    /// matches one of them.
    Regex,
}

/// Per-call analysis options — mirrors the extra keyword args of Presidio's
/// `AnalyzerEngine.analyze` (`allow_list`, `ad_hoc_recognizers`, `context`, ...).
#[derive(Default)]
pub struct AnalyzeOptions<'a> {
    /// Restrict detection to these entity types (`None` = all).
    pub entities: Option<Vec<String>>,
    /// Drop results below this score (`None` = engine default).
    pub score_threshold: Option<f64>,
    /// Words/patterns whose matched text should be treated as non-PII and removed.
    pub allow_list: Vec<String>,
    pub allow_list_match: AllowListMatch,
    /// Extra context words that boost any nearby result (in addition to each
    /// recognizer's own context).
    pub context: Vec<String>,
    /// Recognizers used only for this call, in addition to the registry.
    pub ad_hoc_recognizers: Vec<&'a dyn EntityRecognizer>,
}

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

    /// Detect PII in `text` (simple form).
    pub fn analyze(
        &self,
        text: &str,
        language: &str,
        entities: Option<&[String]>,
        score_threshold: Option<f64>,
    ) -> Vec<RecognizerResult> {
        self.analyze_with(
            text,
            language,
            &AnalyzeOptions {
                entities: entities.map(|e| e.to_vec()),
                score_threshold,
                ..Default::default()
            },
        )
    }

    /// Detect PII in `text` with full [`AnalyzeOptions`].
    pub fn analyze_with(
        &self,
        text: &str,
        language: &str,
        opts: &AnalyzeOptions,
    ) -> Vec<RecognizerResult> {
        // Entity universe = registry entities plus any the ad-hoc recognizers add.
        let mut all_entities = self.registry.supported_entities(language);
        for rec in &opts.ad_hoc_recognizers {
            for e in rec.supported_entities() {
                if !all_entities.contains(&e) {
                    all_entities.push(e);
                }
            }
        }
        let requested: Vec<String> = match &opts.entities {
            Some(e) => e.clone(),
            None => all_entities,
        };

        let nlp = self.nlp_engine.process(text, language);

        let mut results: Vec<RecognizerResult> = Vec::new();
        let registry_recs = self.registry.get_recognizers(language, &requested);
        let ad_hoc = opts
            .ad_hoc_recognizers
            .iter()
            .copied()
            .filter(|r| r.supported_language() == language);

        for recognizer in registry_recs.into_iter().chain(ad_hoc) {
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

        self.context_enhancer
            .enhance(&mut results, &nlp, &opts.context);

        let threshold = opts.score_threshold.unwrap_or(self.default_score_threshold);
        results.retain(|r| r.score >= threshold);

        if !opts.allow_list.is_empty() {
            results = apply_allow_list(text, results, &opts.allow_list, opts.allow_list_match);
        }

        let mut results = remove_conflicts(results);
        results.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));
        results
    }
}

/// Remove results whose matched text is allow-listed.
fn apply_allow_list(
    text: &str,
    results: Vec<RecognizerResult>,
    allow_list: &[String],
    mode: AllowListMatch,
) -> Vec<RecognizerResult> {
    match mode {
        AllowListMatch::Exact => {
            let allow: Vec<String> = allow_list.iter().map(|s| s.to_lowercase()).collect();
            results
                .into_iter()
                .filter(|r| !allow.contains(&text[r.start..r.end].to_lowercase()))
                .collect()
        }
        AllowListMatch::Regex => {
            let regexes: Vec<Regex> = allow_list
                .iter()
                .filter_map(|s| Regex::new(s).ok())
                .collect();
            results
                .into_iter()
                .filter(|r| {
                    let matched = &text[r.start..r.end];
                    !regexes.iter().any(|re| {
                        re.find(matched)
                            .is_some_and(|m| m.start() == 0 && m.end() == matched.len())
                    })
                })
                .collect()
        }
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
