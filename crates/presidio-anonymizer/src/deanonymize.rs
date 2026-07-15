//! [`DeanonymizeEngine`] — reverses reversible operators (e.g. `decrypt`).
//!
//! Port of `presidio_anonymizer.DeanonymizeEngine`.

use std::collections::HashMap;

use serde_json::Value;

use crate::engine::resolve_config;
use crate::entities::{EngineResult, OperatorConfig, OperatorResult};
use crate::factory::OperatorsFactory;
use crate::operator::OperatorType;

pub struct DeanonymizeEngine {
    factory: OperatorsFactory,
}

impl Default for DeanonymizeEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl DeanonymizeEngine {
    pub fn new() -> Self {
        Self {
            factory: OperatorsFactory::new(),
        }
    }

    pub fn factory_mut(&mut self) -> &mut OperatorsFactory {
        &mut self.factory
    }

    /// Deanonymize `text` given the anonymized `entities` (their positions in the
    /// anonymized text) and the deanonymize `operators` to apply per entity type.
    pub fn deanonymize(
        &self,
        text: &str,
        entities: Vec<OperatorResult>,
        operators: &HashMap<String, OperatorConfig>,
    ) -> anyhow::Result<EngineResult> {
        let mut sorted = entities;
        sorted.sort_by_key(|e| e.start);

        let mut output = String::new();
        let mut items: Vec<OperatorResult> = Vec::new();
        let mut last = 0usize;

        for e in &sorted {
            if e.start < last {
                continue;
            }
            output.push_str(&text[last..e.start]);

            let entity_text = &text[e.start..e.end];
            let config = resolve_config(operators, &e.entity_type, "decrypt");
            let operator = self
                .factory
                .get(&config.operator_name, OperatorType::Deanonymize)
                .ok_or_else(|| {
                    anyhow::anyhow!("unknown deanonymize operator `{}`", config.operator_name)
                })?;

            let mut params = config.params.clone();
            params.insert(
                "entity_type".to_string(),
                Value::String(e.entity_type.clone()),
            );
            operator.validate(&params)?;
            let new_text = operator.operate(entity_text, &params)?;

            let start = output.len();
            output.push_str(&new_text);
            let end = output.len();
            items.push(OperatorResult {
                start,
                end,
                entity_type: e.entity_type.clone(),
                text: new_text,
                operator: config.operator_name.clone(),
            });
            last = e.end;
        }
        output.push_str(&text[last..]);

        items.sort_by_key(|i| std::cmp::Reverse(i.start));
        Ok(EngineResult {
            text: output,
            items,
        })
    }
}
