//! [`AnonymizerEngine`] — applies operators over detected entities to produce
//! anonymized text.
//!
//! Port of `presidio_anonymizer.AnonymizerEngine`.

use std::cmp::Ordering;
use std::collections::HashMap;

use serde_json::Value;

use crate::entities::{EngineResult, OperatorConfig, OperatorResult, RecognizerResult};
use crate::factory::OperatorsFactory;
use crate::operator::OperatorType;

pub const DEFAULT_KEY: &str = "DEFAULT";

pub struct AnonymizerEngine {
    factory: OperatorsFactory,
}

impl Default for AnonymizerEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl AnonymizerEngine {
    pub fn new() -> Self {
        Self {
            factory: OperatorsFactory::new(),
        }
    }

    /// Access the underlying factory to register custom operators.
    pub fn factory_mut(&mut self) -> &mut OperatorsFactory {
        &mut self.factory
    }

    /// Anonymize `text` given detected `results` and per-entity `operators`.
    ///
    /// If an entity type has no entry, the `"DEFAULT"` config is used; if that is
    /// also absent, `replace` (`<ENTITY_TYPE>`) is applied.
    pub fn anonymize(
        &self,
        text: &str,
        results: Vec<RecognizerResult>,
        operators: &HashMap<String, OperatorConfig>,
    ) -> anyhow::Result<EngineResult> {
        let mut sorted = remove_conflicts(results);
        sorted.sort_by_key(|r| r.start);

        let mut output = String::new();
        let mut items: Vec<OperatorResult> = Vec::new();
        let mut last = 0usize;

        for r in &sorted {
            if r.start < last {
                continue; // defensive: skip any residual overlap
            }
            output.push_str(&text[last..r.start]);

            let entity_text = &text[r.start..r.end];
            let config = resolve_config(operators, &r.entity_type, "replace");
            let operator = self
                .factory
                .get(&config.operator_name, OperatorType::Anonymize)
                .ok_or_else(|| {
                    anyhow::anyhow!("unknown anonymize operator `{}`", config.operator_name)
                })?;

            let mut params = config.params.clone();
            params.insert(
                "entity_type".to_string(),
                Value::String(r.entity_type.clone()),
            );
            operator.validate(&params)?;
            let new_text = operator.operate(entity_text, &params)?;

            let start = output.len();
            output.push_str(&new_text);
            let end = output.len();
            items.push(OperatorResult {
                start,
                end,
                entity_type: r.entity_type.clone(),
                text: new_text,
                operator: config.operator_name.clone(),
                score: Some(r.score),
            });
            last = r.end;
        }
        output.push_str(&text[last..]);

        // Presidio returns items ordered by descending start.
        items.sort_by_key(|i| std::cmp::Reverse(i.start));
        Ok(EngineResult {
            text: output,
            items,
        })
    }
}

/// Pick the config for an entity: exact match, then `DEFAULT`, then a fallback
/// operator with empty params.
pub(crate) fn resolve_config(
    operators: &HashMap<String, OperatorConfig>,
    entity_type: &str,
    fallback: &str,
) -> OperatorConfig {
    operators
        .get(entity_type)
        .or_else(|| operators.get(DEFAULT_KEY))
        .cloned()
        .unwrap_or_else(|| OperatorConfig::simple(fallback))
}

/// Keep the highest-scoring, non-overlapping set (ties: longer span wins).
pub(crate) fn remove_conflicts(mut results: Vec<RecognizerResult>) -> Vec<RecognizerResult> {
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
