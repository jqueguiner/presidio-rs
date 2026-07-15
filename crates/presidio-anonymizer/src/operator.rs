//! The [`Operator`] trait: base type for every anonymize/deanonymize action.
//!
//! Port of `presidio_anonymizer.operators.operator.Operator`.

use std::collections::HashMap;

use serde_json::Value;

/// Anonymize (text -> redacted) vs Deanonymize (redacted -> text).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatorType {
    Anonymize,
    Deanonymize,
}

pub trait Operator: Send + Sync {
    /// Name used to select this operator from config (e.g. `"replace"`).
    fn operator_name(&self) -> &str;

    fn operator_type(&self) -> OperatorType;

    /// Transform a single entity's `text` using `params`.
    ///
    /// The engine injects an `entity_type` string param before calling, so
    /// operators like `replace` can build a `<ENTITY_TYPE>` default.
    fn operate(&self, text: &str, params: &HashMap<String, Value>) -> anyhow::Result<String>;

    /// Validate params up-front; default accepts anything.
    fn validate(&self, _params: &HashMap<String, Value>) -> anyhow::Result<()> {
        Ok(())
    }
}

/// Read an optional string param.
pub fn str_param<'a>(params: &'a HashMap<String, Value>, key: &str) -> Option<&'a str> {
    params.get(key).and_then(|v| v.as_str())
}

/// Read an optional integer param.
pub fn int_param(params: &HashMap<String, Value>, key: &str) -> Option<i64> {
    params.get(key).and_then(|v| v.as_i64())
}

/// Read an optional bool param.
pub fn bool_param(params: &HashMap<String, Value>, key: &str) -> Option<bool> {
    params.get(key).and_then(|v| v.as_bool())
}
