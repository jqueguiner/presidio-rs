//! # presidio-anonymizer
//!
//! A Rust port of Microsoft Presidio's **anonymization** engine
//! (`presidio-anonymizer`). Given text plus detected entity spans, it applies
//! operators (replace, redact, mask, hash, encrypt, keep, custom) to produce
//! anonymized text — and can reverse the reversible ones (decrypt).
//!
//! ```
//! use std::collections::HashMap;
//! use presidio_anonymizer::{AnonymizerEngine, OperatorConfig, RecognizerResult};
//!
//! let engine = AnonymizerEngine::new();
//! let text = "My name is Bond, James Bond";
//! let results = vec![RecognizerResult::new("PERSON", 11, 27, 0.85)];
//! let mut ops = HashMap::new();
//! ops.insert("PERSON".to_string(), OperatorConfig::simple("redact"));
//! let out = engine.anonymize(text, results, &ops).unwrap();
//! assert_eq!(out.text, "My name is ");
//! ```

pub mod aes_cipher;
pub mod deanonymize;
pub mod engine;
pub mod entities;
pub mod factory;
pub mod operator;
pub mod operators;

pub use deanonymize::DeanonymizeEngine;
pub use engine::AnonymizerEngine;
pub use entities::{EngineResult, OperatorConfig, OperatorResult, RecognizerResult};
pub use factory::OperatorsFactory;
pub use operator::{Operator, OperatorType};
pub use operators::{Custom, Decrypt, Encrypt, Hash, Keep, Mask, Redact, Replace, Surrogate};
