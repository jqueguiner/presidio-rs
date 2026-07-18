//! Gazetteer (name-lookup) recognizer.
//!
//! Detects names by exact token lookup against a large in-memory set, rather
//! than regex. This backs the census-derived `FIRST_NAME` / `LAST_NAME`
//! recognizers, whose sets (~196k / ~794k entries) are far too large for a
//! regex alternation.
//!
//! The convenience constructors and the embedded data live behind the
//! `names-gazetteer` cargo feature (the `GazetteerRecognizer` type itself is
//! always available so callers can build their own gazetteers).

use std::collections::HashSet;
use std::sync::OnceLock;

use regex::Regex;

use crate::entities::{AnalysisExplanation, RecognizerResult};
use crate::nlp::NlpArtifacts;
use crate::recognizer::EntityRecognizer;

/// Word-token matcher: a Unicode letter followed by letters, apostrophes or
/// hyphens (so `O'Brien` and `Jean-Luc` tokenize as single tokens).
fn token_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\p{L}[\p{L}'\-]*").unwrap())
}

/// A recognizer that emits a result for every token found in `names`.
pub struct GazetteerRecognizer {
    name: String,
    entity: String,
    names: HashSet<String>,
    score: f64,
    /// Tokens shorter than this are ignored (cuts high-frequency short-word
    /// false positives like "an", "to").
    min_len: usize,
}

impl GazetteerRecognizer {
    /// Build a gazetteer from an already-lowercased set of names.
    pub fn new(name: &str, entity: &str, names: HashSet<String>, score: f64) -> Self {
        Self {
            name: name.to_string(),
            entity: entity.to_string(),
            names,
            score,
            min_len: 3,
        }
    }

    /// Override the minimum token length (default 3).
    pub fn with_min_len(mut self, min_len: usize) -> Self {
        self.min_len = min_len;
        self
    }

    /// Number of names in the set.
    pub fn len(&self) -> usize {
        self.names.len()
    }

    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }
}

impl EntityRecognizer for GazetteerRecognizer {
    fn name(&self) -> &str {
        &self.name
    }

    fn supported_entities(&self) -> Vec<String> {
        vec![self.entity.clone()]
    }

    fn analyze(
        &self,
        text: &str,
        entities: &[String],
        _nlp: Option<&NlpArtifacts>,
    ) -> Vec<RecognizerResult> {
        if !entities.iter().any(|e| e == &self.entity) {
            return Vec::new();
        }
        let mut out = Vec::new();
        for m in token_regex().find_iter(text) {
            let tok = m.as_str();
            if tok.chars().count() < self.min_len {
                continue;
            }
            if self.names.contains(&tok.to_lowercase()) {
                let mut r =
                    RecognizerResult::new(self.entity.clone(), m.start(), m.end(), self.score);
                r.analysis_explanation = Some(AnalysisExplanation {
                    recognizer: self.name.clone(),
                    original_score: self.score,
                    score: self.score,
                    textual_explanation: Some(format!("token '{tok}' found in gazetteer")),
                    ..Default::default()
                });
                out.push(r);
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Embedded census gazetteers (feature-gated)
// ---------------------------------------------------------------------------

#[cfg(feature = "names-gazetteer")]
fn load_gz(bytes: &[u8]) -> HashSet<String> {
    use std::io::Read;
    let mut s = String::new();
    flate2::read::GzDecoder::new(bytes)
        .read_to_string(&mut s)
        .expect("embedded gazetteer is valid gzip");
    s.lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .map(|l| l.to_string())
        .collect()
}

/// `FIRST_NAME` gazetteer — ~196k multi-country first names from the census DB
/// (probabilities/ranks stripped). Base score 0.3 (medium, standalone).
#[cfg(feature = "names-gazetteer")]
pub fn first_names() -> GazetteerRecognizer {
    let set = load_gz(include_bytes!("../data/first_names.txt.gz"));
    GazetteerRecognizer::new("FirstNameGazetteer", "FIRST_NAME", set, 0.3)
}

/// `LAST_NAME` gazetteer — ~794k multi-country surnames from the census DB
/// (probabilities/ranks stripped). Base score 0.3 (medium, standalone).
#[cfg(feature = "names-gazetteer")]
pub fn last_names() -> GazetteerRecognizer {
    let set = load_gz(include_bytes!("../data/last_names.txt.gz"));
    GazetteerRecognizer::new("LastNameGazetteer", "LAST_NAME", set, 0.3)
}

/// Both census name gazetteers, ready to register.
#[cfg(feature = "names-gazetteer")]
pub fn all_gazetteers() -> Vec<Box<dyn EntityRecognizer>> {
    vec![Box::new(first_names()), Box::new(last_names())]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_matches_tokens() {
        let set: HashSet<String> = ["alice", "bob", "carol"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let rec = GazetteerRecognizer::new("G", "FIRST_NAME", set, 0.3);
        let res = rec.analyze("Alice met bob and Dan", &["FIRST_NAME".to_string()], None);
        // "Alice" (case-insensitive) and "bob"; "Dan" not in set.
        assert_eq!(res.len(), 2);
        assert!(res.iter().all(|r| r.entity_type == "FIRST_NAME"));
        assert_eq!(&"Alice met bob and Dan"[res[0].start..res[0].end], "Alice");
        // Not-requested entity -> empty.
        assert!(rec
            .analyze("Alice", &["LAST_NAME".to_string()], None)
            .is_empty());
    }

    #[test]
    fn min_len_filters_short_tokens() {
        let set: HashSet<String> = ["al"].iter().map(|s| s.to_string()).collect();
        let rec = GazetteerRecognizer::new("G", "FIRST_NAME", set, 0.3);
        // Default min_len 3 drops the 2-char token.
        assert!(rec
            .analyze("al", &["FIRST_NAME".to_string()], None)
            .is_empty());
        let rec2 = rec.with_min_len(2);
        assert_eq!(
            rec2.analyze("al", &["FIRST_NAME".to_string()], None).len(),
            1
        );
    }

    #[cfg(feature = "names-gazetteer")]
    #[test]
    fn census_gazetteers_load_and_detect() {
        let fnr = first_names();
        assert!(fnr.len() > 150_000);
        let res = fnr.analyze("my name is Maria", &["FIRST_NAME".to_string()], None);
        assert!(res.iter().any(|r| r.entity_type == "FIRST_NAME"));

        let lnr = last_names();
        assert!(lnr.len() > 100_000);
        let res = lnr.analyze("mr Smith", &["LAST_NAME".to_string()], None);
        assert!(res.iter().any(|r| r.entity_type == "LAST_NAME"));
    }
}
