//! Regex pattern with an associated name and base confidence score.
//!
//! Mirrors `presidio_analyzer.pattern.Pattern`.

use regex::Regex;

#[derive(Debug, Clone)]
pub struct Pattern {
    pub name: String,
    pub regex: Regex,
    pub score: f64,
}

impl Pattern {
    /// Compile a pattern. Panics on an invalid regex — patterns are static and
    /// defined in-crate, so a bad regex is a programmer error caught at startup.
    pub fn new(name: &str, regex: &str, score: f64) -> Self {
        Self {
            name: name.to_string(),
            regex: Regex::new(regex).unwrap_or_else(|e| panic!("invalid pattern `{name}`: {e}")),
            score,
        }
    }
}
