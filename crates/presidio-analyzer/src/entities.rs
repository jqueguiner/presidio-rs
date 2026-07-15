//! Core value types produced by the analyzer.
//!
//! Mirrors `presidio_analyzer.recognizer_result.RecognizerResult` and
//! `presidio_analyzer.analysis_explanation.AnalysisExplanation`.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Highest score a recognizer may assign.
pub const MAX_SCORE: f64 = 1.0;
/// Lowest score a recognizer may assign.
pub const MIN_SCORE: f64 = 0.0;

/// Human-readable trace of *why* a result was produced and scored the way it was.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnalysisExplanation {
    pub recognizer: String,
    pub pattern_name: Option<String>,
    pub pattern: Option<String>,
    pub original_score: f64,
    pub score: f64,
    pub textual_explanation: Option<String>,
    pub score_context_improvement: f64,
    pub supportive_context_word: Option<String>,
    pub validation_result: Option<bool>,
}

/// A single detected PII entity within a piece of text.
///
/// `start`/`end` are **byte** offsets into the analyzed string (half-open range,
/// like Python's `[start:end]` for ASCII, and always on UTF-8 char boundaries
/// because they originate from regex match spans / token spans).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecognizerResult {
    pub entity_type: String,
    pub start: usize,
    pub end: usize,
    pub score: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analysis_explanation: Option<AnalysisExplanation>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub recognition_metadata: HashMap<String, String>,
    /// Context words that support this entity (used by the context enhancer).
    /// Not part of the serialized output.
    #[serde(skip)]
    pub context: Vec<String>,
}

impl RecognizerResult {
    pub fn new(entity_type: impl Into<String>, start: usize, end: usize, score: f64) -> Self {
        Self {
            entity_type: entity_type.into(),
            start,
            end,
            score,
            analysis_explanation: None,
            recognition_metadata: HashMap::new(),
            context: Vec::new(),
        }
    }

    /// Length of the matched span in bytes.
    pub fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// True if `self` fully contains `other`.
    pub fn contains(&self, other: &Self) -> bool {
        self.start <= other.start && self.end >= other.end
    }

    /// True if the two spans overlap at all.
    pub fn intersects(&self, other: &Self) -> bool {
        self.start < other.end && other.start < self.end
    }

    /// True if both spans cover the exact same range.
    pub fn same_span(&self, other: &Self) -> bool {
        self.start == other.start && self.end == other.end
    }
}
