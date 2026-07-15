//! # presidio-analyzer
//!
//! A Rust port of Microsoft Presidio's PII **detection** engine
//! (`presidio-analyzer`).
//!
//! ```
//! use presidio_analyzer::AnalyzerEngine;
//!
//! let engine = AnalyzerEngine::new();
//! let results = engine.analyze(
//!     "My card is 4095-2609-9393-4932 and email a@b.com",
//!     "en",
//!     None,
//!     None,
//! );
//! assert!(results.iter().any(|r| r.entity_type == "CREDIT_CARD"));
//! assert!(results.iter().any(|r| r.entity_type == "EMAIL_ADDRESS"));
//! ```
//!
//! ## Architecture (mirrors the Python package)
//! * [`Pattern`] / [`PatternRecognizer`] — regex + optional checksum validator
//! * [`predefined`] — the built-in recognizers (credit card, IBAN, crypto, ...)
//! * [`nlp`] — pluggable NLP/NER seam ([`NlpEngine`]); real NER slots in here
//! * [`context`] — lemma-based context score enhancement
//! * [`RecognizerRegistry`] / [`AnalyzerEngine`] — orchestration

pub mod analyzer_engine;
pub mod context;
pub mod entities;
pub mod ner_recognizer;
pub mod nlp;
pub mod pattern;
pub mod predefined;
pub mod recognizer;
pub mod registry;
pub mod validators;

pub use analyzer_engine::AnalyzerEngine;
pub use context::LemmaContextAwareEnhancer;
pub use entities::{AnalysisExplanation, RecognizerResult, MAX_SCORE, MIN_SCORE};
pub use ner_recognizer::NerRecognizer;
pub use nlp::{NerEntity, NlpArtifacts, NlpEngine, SimpleNlpEngine, Token};
pub use pattern::Pattern;
pub use recognizer::{EntityRecognizer, PatternRecognizer, Validator};
pub use registry::RecognizerRegistry;
