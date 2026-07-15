//! NLP abstraction layer.
//!
//! Presidio's analyzer delegates tokenization, lemmatization and NER to a
//! pluggable `NlpEngine` (spaCy / stanza / transformers). This module defines
//! the same seam in Rust: [`NlpEngine`] is a trait, so a real transformer-based
//! backend (e.g. `rust-bert` / ONNX) can be dropped in without touching the
//! recognizers. [`SimpleNlpEngine`] ships as a dependency-free default that
//! tokenizes + lemmatizes (lowercases) but performs no NER.

use std::collections::HashSet;

/// A single token with byte offsets into the source text.
#[derive(Debug, Clone)]
pub struct Token {
    pub text: String,
    pub lemma: String,
    pub start: usize,
    pub end: usize,
    pub is_stop: bool,
}

/// A named entity emitted by an NER model.
#[derive(Debug, Clone)]
pub struct NerEntity {
    pub entity_type: String,
    pub start: usize,
    pub end: usize,
    pub score: f64,
}

/// Everything the NLP layer extracted from one document.
#[derive(Debug, Clone, Default)]
pub struct NlpArtifacts {
    pub tokens: Vec<Token>,
    pub entities: Vec<NerEntity>,
    pub language: String,
}

/// Pluggable NLP backend. Implement this to add real NER.
pub trait NlpEngine: Send + Sync {
    fn process(&self, text: &str, language: &str) -> NlpArtifacts;
    fn is_available(&self, _language: &str) -> bool {
        true
    }
}

/// Minimal, dependency-free NLP engine: whitespace/punctuation tokenizer with
/// lowercase lemmas and a small English stop-word list. Emits no NER entities.
pub struct SimpleNlpEngine {
    stop_words: HashSet<&'static str>,
}

impl Default for SimpleNlpEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl SimpleNlpEngine {
    pub fn new() -> Self {
        const STOP: &[&str] = &[
            "a", "an", "and", "are", "as", "at", "be", "by", "for", "from", "has", "he", "in",
            "is", "it", "its", "of", "on", "that", "the", "to", "was", "were", "will", "with",
            "my", "your", "his", "her", "our", "their", "this", "these", "those",
        ];
        Self {
            stop_words: STOP.iter().copied().collect(),
        }
    }
}

impl NlpEngine for SimpleNlpEngine {
    fn process(&self, text: &str, language: &str) -> NlpArtifacts {
        let mut tokens = Vec::new();
        let mut start: Option<usize> = None;

        // A token is a maximal run of alphanumeric (Unicode) characters or '_'.
        for (idx, ch) in text.char_indices() {
            if ch.is_alphanumeric() || ch == '_' {
                if start.is_none() {
                    start = Some(idx);
                }
            } else if let Some(s) = start.take() {
                push_token(&mut tokens, text, s, idx, &self.stop_words);
            }
        }
        if let Some(s) = start {
            push_token(&mut tokens, text, s, text.len(), &self.stop_words);
        }

        NlpArtifacts {
            tokens,
            entities: Vec::new(),
            language: language.to_string(),
        }
    }
}

fn push_token(
    tokens: &mut Vec<Token>,
    text: &str,
    start: usize,
    end: usize,
    stop_words: &HashSet<&'static str>,
) {
    let raw = &text[start..end];
    let lemma = raw.to_lowercase();
    let is_stop = stop_words.contains(lemma.as_str());
    tokens.push(Token {
        text: raw.to_string(),
        lemma,
        start,
        end,
        is_stop,
    });
}
