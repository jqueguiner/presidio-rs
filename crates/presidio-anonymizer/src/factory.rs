//! Operator registry keyed by name + direction.
//!
//! Port of `presidio_anonymizer.operators.operators_factory.OperatorsFactory`.

use std::collections::HashMap;

use crate::operator::{Operator, OperatorType};
use crate::operators::{Decrypt, Encrypt, Hash, Keep, Mask, Redact, Replace};

pub struct OperatorsFactory {
    anonymizers: HashMap<String, Box<dyn Operator>>,
    deanonymizers: HashMap<String, Box<dyn Operator>>,
}

impl Default for OperatorsFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl OperatorsFactory {
    /// Factory preloaded with all built-in operators.
    pub fn new() -> Self {
        let mut f = Self {
            anonymizers: HashMap::new(),
            deanonymizers: HashMap::new(),
        };
        f.add(Box::new(Replace));
        f.add(Box::new(Redact));
        f.add(Box::new(Mask));
        f.add(Box::new(Hash));
        f.add(Box::new(Keep));
        f.add(Box::new(Encrypt));
        f.add(Box::new(Decrypt));
        f
    }

    /// Register (or override) an operator. Routed by its declared type.
    pub fn add(&mut self, op: Box<dyn Operator>) {
        let name = op.operator_name().to_string();
        match op.operator_type() {
            OperatorType::Anonymize => {
                self.anonymizers.insert(name, op);
            }
            OperatorType::Deanonymize => {
                self.deanonymizers.insert(name, op);
            }
        }
    }

    pub fn get(&self, name: &str, op_type: OperatorType) -> Option<&dyn Operator> {
        let map = match op_type {
            OperatorType::Anonymize => &self.anonymizers,
            OperatorType::Deanonymize => &self.deanonymizers,
        };
        map.get(name).map(|b| b.as_ref())
    }

    pub fn operator_names(&self, op_type: OperatorType) -> Vec<String> {
        let map = match op_type {
            OperatorType::Anonymize => &self.anonymizers,
            OperatorType::Deanonymize => &self.deanonymizers,
        };
        let mut v: Vec<String> = map.keys().cloned().collect();
        v.sort();
        v
    }
}
