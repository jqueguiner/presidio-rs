//! Phone-number recognizer backed by the `phonenumber-rs` crate (a Rust rewrite
//! of Google's libphonenumber), replacing the earlier US-only regex.
//!
//! Port of `presidio_analyzer.predefined_recognizers.PhoneRecognizer`, which
//! runs libphonenumber's `PhoneNumberMatcher` (leniency `VALID`) across a set of
//! default regions. The Rust crate exposes no matcher, so we approximate it:
//!  1. pull phone-like candidates out of the text with a broad regex,
//!  2. parse + validate each against the configured regions,
//!  3. apply a leniency filter that emulates `Leniency.VALID`'s grouping check —
//!     numbers written with an explicit `+CC` are accepted outright, while bare
//!     national-format candidates must have a digit-group shape matching the
//!     number's own national formatting. That last step is what stops SSNs and
//!     dates (e.g. `078-05-1120`, `12/05/2020`) from validating as phone numbers
//!     in permissive regions, which in turn lets us keep Presidio's full default
//!     region list rather than narrowing it.

use once_cell_regex::CANDIDATE;
use phonenumber::{format_national, is_valid_number, parse, PhoneNumber};

use crate::entities::{AnalysisExplanation, RecognizerResult};
use crate::nlp::NlpArtifacts;
use crate::recognizer::EntityRecognizer;

mod once_cell_regex {
    use regex::Regex;
    use std::sync::OnceLock;

    static CELL: OnceLock<Regex> = OnceLock::new();

    /// A phone number is a `+`-optional run of 7+ digits interspersed with the
    /// usual separators. Deliberately broad — `phonenumber` does the real work.
    #[allow(non_snake_case)]
    pub fn CANDIDATE() -> &'static Regex {
        CELL.get_or_init(|| {
            Regex::new(r"\+?\(?\d[\d\-\.\s()]{6,}\d").expect("valid candidate regex")
        })
    }
}

pub struct PhoneRecognizer {
    pub name: String,
    pub entity: String,
    pub language: String,
    pub regions: Vec<&'static str>,
    pub context: Vec<String>,
    pub score: f64,
}

impl Default for PhoneRecognizer {
    fn default() -> Self {
        Self {
            name: "PhoneRecognizer".to_string(),
            entity: "PHONE_NUMBER".to_string(),
            language: "en".to_string(),
            // Presidio's DEFAULT_SUPPORTED_REGIONS. Safe to keep broad because
            // the grouping-leniency filter below rejects non-phone digit shapes.
            // Broad default region set: for multilingual PII, national-format
            // numbers only validate under their own region, so 8 regions missed
            // most non-US/UK numbers. libphonenumber still validates each
            // candidate (the grouping-leniency filter below rejects non-phone
            // shapes), so widening regions lifts recall without opening the door
            // to SSN/date false positives.
            regions: vec![
                "US", "GB", "CA", "AU", "IE", "NZ", "ZA", "IN", "DE", "FR", "IT", "ES", "PT",
                "NL", "BE", "CH", "AT", "SE", "NO", "DK", "FI", "PL", "CZ", "RO", "HU", "GR",
                "TR", "RU", "IL", "BR", "MX", "AR", "JP", "CN", "KR", "SG", "MY", "PH", "ID",
                "TH",
            ],
            context: [
                "phone",
                "number",
                "telephone",
                "cell",
                "mobile",
                "call",
                "tel",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            score: 0.75,
        }
    }
}

/// Lengths of each maximal run of ASCII digits (the "grouping shape").
fn group_lengths(s: &str) -> Vec<usize> {
    let mut groups = Vec::new();
    let mut run = 0usize;
    for ch in s.chars() {
        if ch.is_ascii_digit() {
            run += 1;
        } else if run > 0 {
            groups.push(run);
            run = 0;
        }
    }
    if run > 0 {
        groups.push(run);
    }
    groups
}

/// Does the candidate contain a grouping separator (anything but digits / `+`)?
fn has_separator(s: &str) -> bool {
    s.chars().any(|c| !c.is_ascii_digit() && c != '+')
}

impl PhoneRecognizer {
    /// Emulates libphonenumber `Leniency.VALID`:
    /// * `+CC` numbers are unambiguous → accept once valid;
    /// * a bare digit run (no separators) → accept once valid;
    /// * a separated national candidate → accept only if its digit-group shape
    ///   matches the number's national formatting (rejects SSN/date shapes).
    fn passes_leniency(candidate: &str, number: &PhoneNumber) -> bool {
        let cand = candidate.trim();
        if cand.starts_with('+') || !has_separator(cand) {
            return true;
        }
        let national = format_national(number);
        group_lengths(cand) == group_lengths(&national)
    }
}

impl EntityRecognizer for PhoneRecognizer {
    fn name(&self) -> &str {
        &self.name
    }

    fn supported_entities(&self) -> Vec<String> {
        vec![self.entity.clone()]
    }

    fn supported_language(&self) -> &str {
        &self.language
    }

    fn is_language_agnostic(&self) -> bool {
        true
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
        for m in CANDIDATE().find_iter(text) {
            let candidate = m.as_str();
            for &region in &self.regions {
                match parse(Some(region), candidate) {
                    Ok(number)
                        if is_valid_number(&number)
                            && Self::passes_leniency(candidate, &number) =>
                    {
                        let mut r = RecognizerResult::new(
                            self.entity.clone(),
                            m.start(),
                            m.end(),
                            self.score,
                        );
                        r.analysis_explanation = Some(AnalysisExplanation {
                            recognizer: self.name.clone(),
                            textual_explanation: Some(format!(
                                "validated as a {region} phone number"
                            )),
                            original_score: self.score,
                            score: self.score,
                            validation_result: Some(true),
                            ..Default::default()
                        });
                        r.context = self.context.clone();
                        out.push(r);
                        break; // first accepting region wins
                    }
                    _ => {}
                }
            }
        }
        out
    }
}
