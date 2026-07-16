//! Recognizer registry — the catalog of recognizers the engine consults.
//!
//! Port of `presidio_analyzer.RecognizerRegistry`.

use crate::country;
use crate::ner_recognizer::NerRecognizer;
use crate::phone_recognizer::PhoneRecognizer;
use crate::predefined;
use crate::recognizer::EntityRecognizer;

pub struct RecognizerRegistry {
    pub recognizers: Vec<Box<dyn EntityRecognizer>>,
}

impl Default for RecognizerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl RecognizerRegistry {
    pub fn new() -> Self {
        Self {
            recognizers: Vec::new(),
        }
    }

    /// Registry preloaded with every predefined recognizer plus the NER seam.
    pub fn with_predefined(language: &str) -> Self {
        let mut reg = Self::new();
        reg.load_predefined(language);
        reg
    }

    pub fn add(&mut self, recognizer: Box<dyn EntityRecognizer>) {
        self.recognizers.push(recognizer);
    }

    pub fn load_predefined(&mut self, language: &str) {
        if language == "en" {
            for r in predefined::all_english() {
                self.recognizers.push(r);
            }
            for r in country::all_country() {
                self.recognizers.push(r);
            }
            self.recognizers.push(Box::new(PhoneRecognizer::default()));
            self.recognizers.push(Box::new(NerRecognizer::default()));
        }
    }

    /// Distinct entity types supported for `language`.
    pub fn supported_entities(&self, language: &str) -> Vec<String> {
        let mut entities: Vec<String> = self
            .recognizers
            .iter()
            .filter(|r| r.supported_language() == language || r.is_language_agnostic())
            .flat_map(|r| r.supported_entities())
            .collect();
        entities.sort();
        entities.dedup();
        entities
    }

    /// Recognizers active for `language` that can produce at least one of `entities`.
    pub fn get_recognizers(
        &self,
        language: &str,
        entities: &[String],
    ) -> Vec<&dyn EntityRecognizer> {
        self.recognizers
            .iter()
            .filter(|r| r.supported_language() == language || r.is_language_agnostic())
            .filter(|r| {
                r.supported_entities()
                    .iter()
                    .any(|e| entities.iter().any(|want| want == e))
            })
            .map(|b| b.as_ref())
            .collect()
    }
}
