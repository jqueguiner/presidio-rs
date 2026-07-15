//! Value types for the anonymizer.
//!
//! The anonymizer package intentionally has its own `RecognizerResult` (it does
//! not depend on the analyzer), matching Presidio's package boundary.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A span to operate on. Only the fields the anonymizer needs are kept.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecognizerResult {
    pub entity_type: String,
    pub start: usize,
    pub end: usize,
    pub score: f64,
}

impl RecognizerResult {
    pub fn new(entity_type: impl Into<String>, start: usize, end: usize, score: f64) -> Self {
        Self {
            entity_type: entity_type.into(),
            start,
            end,
            score,
        }
    }

    pub fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn contains(&self, other: &Self) -> bool {
        self.start <= other.start && self.end >= other.end
    }

    pub fn intersects(&self, other: &Self) -> bool {
        self.start < other.end && other.start < self.end
    }
}

/// Which operator to apply to an entity, and its parameters.
///
/// Mirrors `presidio_anonymizer.entities.OperatorConfig`.
#[derive(Debug, Clone)]
pub struct OperatorConfig {
    pub operator_name: String,
    pub params: HashMap<String, Value>,
}

impl OperatorConfig {
    pub fn new(operator_name: impl Into<String>, params: HashMap<String, Value>) -> Self {
        Self {
            operator_name: operator_name.into(),
            params,
        }
    }

    /// Config with no parameters (operator uses its defaults).
    pub fn simple(operator_name: impl Into<String>) -> Self {
        Self::new(operator_name, HashMap::new())
    }

    pub fn param(mut self, key: &str, value: Value) -> Self {
        self.params.insert(key.to_string(), value);
        self
    }
}

/// One applied operation in the result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorResult {
    pub start: usize,
    pub end: usize,
    pub entity_type: String,
    pub text: String,
    pub operator: String,
}

/// Output of an (de)anonymization run: the transformed text and per-entity items.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineResult {
    pub text: String,
    pub items: Vec<OperatorResult>,
}
