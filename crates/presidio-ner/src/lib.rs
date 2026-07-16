//! # presidio-ner
//!
//! Optional [Candle](https://github.com/huggingface/candle)-based NER backend for
//! [`presidio-analyzer`]. Pure Rust — no external ML runtime. Implements
//! [`presidio_analyzer::NlpEngine`], so plugging it in lights up `PERSON`,
//! `LOCATION`, `ORGANIZATION` and `NRP` with no changes to the analyzer:
//!
//! ```no_run
//! use presidio_analyzer::AnalyzerEngine;
//! use presidio_ner::TransformerNerEngine;
//!
//! let ner = TransformerNerEngine::from_pretrained("dslim/bert-base-NER")?;
//! let engine = AnalyzerEngine::new().with_nlp_engine(Box::new(ner));
//! let results = engine.analyze("John Smith lives in Paris", "en", None, None);
//! # Ok::<(), anyhow::Error>(())
//! ```
//!
//! Model weights are **not** bundled: [`TransformerNerEngine::from_pretrained`]
//! lazily downloads them from the Hugging Face Hub (cached under
//! `~/.cache/huggingface`), and [`TransformerNerEngine::from_path`] loads a local
//! directory.

pub mod decode;
mod engine;

pub use engine::TransformerNerEngine;
