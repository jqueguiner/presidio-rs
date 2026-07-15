//! Recognizer abstractions.
//!
//! [`EntityRecognizer`] is the object-safe trait every recognizer implements.
//! [`PatternRecognizer`] is the concrete, regex-driven recognizer that backs all
//! predefined recognizers — mirroring `presidio_analyzer.PatternRecognizer`.

use crate::entities::{AnalysisExplanation, RecognizerResult, MAX_SCORE};
use crate::nlp::NlpArtifacts;
use crate::pattern::Pattern;
use regex::Regex;

/// A pure-function result validator (see [`crate::validators`]).
pub type Validator = fn(&str) -> Option<bool>;

/// Object-safe recognizer interface. Registry stores `Box<dyn EntityRecognizer>`.
pub trait EntityRecognizer: Send + Sync {
    fn name(&self) -> &str;
    fn supported_entities(&self) -> Vec<String>;
    fn supported_language(&self) -> &str {
        "en"
    }
    /// Analyze `text`, restricted to the requested `entities`. `nlp` gives access
    /// to tokens / NER artifacts (may be `None` for recognizers that don't need it).
    fn analyze(
        &self,
        text: &str,
        entities: &[String],
        nlp: Option<&NlpArtifacts>,
    ) -> Vec<RecognizerResult>;
}

/// Regex + optional checksum validator + deny-list recognizer.
pub struct PatternRecognizer {
    pub name: String,
    pub supported_entity: String,
    pub supported_language: String,
    pub patterns: Vec<Pattern>,
    pub context: Vec<String>,
    pub validator: Option<Validator>,
    pub deny_list: Vec<String>,
    pub deny_list_score: f64,
}

impl PatternRecognizer {
    pub fn new(name: &str, entity: &str, patterns: Vec<Pattern>) -> Self {
        Self {
            name: name.to_string(),
            supported_entity: entity.to_string(),
            supported_language: "en".to_string(),
            patterns,
            context: Vec::new(),
            validator: None,
            deny_list: Vec::new(),
            deny_list_score: 1.0,
        }
    }

    pub fn with_context(mut self, context: &[&str]) -> Self {
        self.context = context.iter().map(|s| s.to_string()).collect();
        self
    }

    pub fn with_validator(mut self, v: Validator) -> Self {
        self.validator = Some(v);
        self
    }

    pub fn with_deny_list(mut self, words: &[&str], score: f64) -> Self {
        self.deny_list = words.iter().map(|s| s.to_string()).collect();
        self.deny_list_score = score;
        self
    }

    fn wanted(&self, entities: &[String]) -> bool {
        entities.iter().any(|e| e == &self.supported_entity)
    }
}

impl EntityRecognizer for PatternRecognizer {
    fn name(&self) -> &str {
        &self.name
    }

    fn supported_entities(&self) -> Vec<String> {
        vec![self.supported_entity.clone()]
    }

    fn supported_language(&self) -> &str {
        &self.supported_language
    }

    fn analyze(
        &self,
        text: &str,
        entities: &[String],
        _nlp: Option<&NlpArtifacts>,
    ) -> Vec<RecognizerResult> {
        if !self.wanted(entities) {
            return Vec::new();
        }
        let mut out: Vec<RecognizerResult> = Vec::new();

        for pat in &self.patterns {
            for m in pat.regex.find_iter(text) {
                let matched = &text[m.start()..m.end()];
                let mut score = pat.score.min(MAX_SCORE);
                let mut validation: Option<bool> = None;

                if let Some(validate) = self.validator {
                    match validate(matched) {
                        Some(true) => {
                            score = MAX_SCORE;
                            validation = Some(true);
                        }
                        Some(false) => continue, // invalid match: drop it
                        None => {}
                    }
                }

                out.push(self.build_result(pat, m.start(), m.end(), score, validation));
            }
        }

        self.scan_deny_list(text, &mut out);
        remove_contained(out)
    }
}

impl PatternRecognizer {
    fn build_result(
        &self,
        pat: &Pattern,
        start: usize,
        end: usize,
        score: f64,
        validation: Option<bool>,
    ) -> RecognizerResult {
        let mut r = RecognizerResult::new(self.supported_entity.clone(), start, end, score);
        r.analysis_explanation = Some(AnalysisExplanation {
            recognizer: self.name.clone(),
            pattern_name: Some(pat.name.clone()),
            pattern: Some(pat.regex.as_str().to_string()),
            original_score: pat.score,
            score,
            validation_result: validation,
            ..Default::default()
        });
        r.context = self.context.clone();
        r
    }

    fn scan_deny_list(&self, text: &str, out: &mut Vec<RecognizerResult>) {
        if self.deny_list.is_empty() {
            return;
        }
        let alt = self
            .deny_list
            .iter()
            .map(|w| regex::escape(w))
            .collect::<Vec<_>>()
            .join("|");
        let re = match Regex::new(&format!(r"(?i)\b(?:{alt})\b")) {
            Ok(re) => re,
            Err(_) => return,
        };
        for m in re.find_iter(text) {
            let mut r = RecognizerResult::new(
                self.supported_entity.clone(),
                m.start(),
                m.end(),
                self.deny_list_score,
            );
            r.context = self.context.clone();
            out.push(r);
        }
    }
}

/// Drop results fully contained within another equal-or-higher-scoring result
/// from the *same* recognizer (intra-recognizer de-duplication).
pub(crate) fn remove_contained(mut results: Vec<RecognizerResult>) -> Vec<RecognizerResult> {
    results.sort_by(|a, b| {
        a.start
            .cmp(&b.start)
            .then_with(|| b.len().cmp(&a.len()))
            .then_with(|| {
                b.score
                    .partial_cmp(&a.score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    });
    let mut kept: Vec<RecognizerResult> = Vec::new();
    for r in results {
        let dominated = kept
            .iter()
            .any(|k| k.contains(&r) && k.score >= r.score && !(k.same_span(&r)));
        let exact_dup = kept.iter().any(|k| k.same_span(&r) && k.score >= r.score);
        if !dominated && !exact_dup {
            kept.push(r);
        }
    }
    kept
}
