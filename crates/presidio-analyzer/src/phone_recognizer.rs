//! Phone-number recognizer backed by the `phonenumber` crate (a Rust port of
//! Google's libphonenumber), replacing the earlier US-only regex.
//!
//! Port of `presidio_analyzer.predefined_recognizers.PhoneRecognizer`, which
//! uses libphonenumber's matcher across a set of default regions. Here we pull
//! phone-like candidates out of the text with a broad regex, then confirm each
//! by parsing + validating against the configured regions.

use once_cell_regex::CANDIDATE;
use phonenumber::country;

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
    pub regions: Vec<country::Id>,
    // (Id is Copy; the vec is small and cloned rarely.)
    pub context: Vec<String>,
    pub score: f64,
}

impl Default for PhoneRecognizer {
    fn default() -> Self {
        Self {
            name: "PhoneRecognizer".to_string(),
            entity: "PHONE_NUMBER".to_string(),
            language: "en".to_string(),
            // Default regions kept deliberately tight to limit false positives
            // (permissive regions happily "validate" SSNs / dates). Numbers that
            // carry an explicit +CC country code still parse correctly against
            // any of these, so international detection is preserved; add regions
            // via `PhoneRecognizer { regions, .. }` when national-format numbers
            // from other countries must be caught.
            regions: vec![country::Id::US, country::Id::GB],
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
            for region in &self.regions {
                match phonenumber::parse(Some(*region), candidate) {
                    Ok(number) if phonenumber::is_valid(&number) => {
                        let mut r = RecognizerResult::new(
                            self.entity.clone(),
                            m.start(),
                            m.end(),
                            self.score,
                        );
                        r.analysis_explanation = Some(AnalysisExplanation {
                            recognizer: self.name.clone(),
                            textual_explanation: Some(format!(
                                "validated as a {region:?} phone number"
                            )),
                            original_score: self.score,
                            score: self.score,
                            validation_result: Some(true),
                            ..Default::default()
                        });
                        r.context = self.context.clone();
                        out.push(r);
                        break; // first valid region wins
                    }
                    _ => {}
                }
            }
        }
        out
    }
}
