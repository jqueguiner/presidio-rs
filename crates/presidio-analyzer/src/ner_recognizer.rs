//! Turns NER entities produced by an [`NlpEngine`](crate::nlp::NlpEngine) into
//! [`RecognizerResult`]s. Analogous to Presidio's `SpacyRecognizer` /
//! `TransformersRecognizer`: the model does the detection, this maps its labels
//! onto Presidio entity names.
//!
//! With the default [`SimpleNlpEngine`](crate::nlp::SimpleNlpEngine) (no NER)
//! this recognizer is inert; wire a real backend and it starts producing
//! PERSON / LOCATION / ORGANIZATION / etc. results.

use std::collections::HashMap;

use crate::entities::RecognizerResult;
use crate::nlp::NlpArtifacts;
use crate::recognizer::EntityRecognizer;

pub struct NerRecognizer {
    pub name: String,
    pub language: String,
    /// Maps model label -> Presidio entity name (e.g. `PER` -> `PERSON`).
    pub label_map: HashMap<String, String>,
}

impl Default for NerRecognizer {
    fn default() -> Self {
        let mut label_map = HashMap::new();
        for (k, v) in [
            ("PERSON", "PERSON"),
            ("PER", "PERSON"),
            ("LOC", "LOCATION"),
            ("LOCATION", "LOCATION"),
            ("GPE", "LOCATION"),
            ("ORG", "ORGANIZATION"),
            ("ORGANIZATION", "ORGANIZATION"),
            ("NORP", "NRP"),
            ("DATE", "DATE_TIME"),
            ("TIME", "DATE_TIME"),
        ] {
            label_map.insert(k.to_string(), v.to_string());
        }
        Self {
            name: "NerRecognizer".to_string(),
            language: "en".to_string(),
            label_map,
        }
    }
}

impl EntityRecognizer for NerRecognizer {
    fn name(&self) -> &str {
        &self.name
    }

    fn supported_entities(&self) -> Vec<String> {
        let mut v: Vec<String> = self.label_map.values().cloned().collect();
        v.sort();
        v.dedup();
        v
    }

    fn supported_language(&self) -> &str {
        &self.language
    }

    fn analyze(
        &self,
        _text: &str,
        entities: &[String],
        nlp: Option<&NlpArtifacts>,
    ) -> Vec<RecognizerResult> {
        let Some(nlp) = nlp else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for ent in &nlp.entities {
            let Some(mapped) = self.label_map.get(&ent.entity_type) else {
                continue;
            };
            if !entities.iter().any(|e| e == mapped) {
                continue;
            }
            let mut r = RecognizerResult::new(mapped.clone(), ent.start, ent.end, ent.score);
            r.recognition_metadata
                .insert("recognizer_name".to_string(), self.name.clone());
            out.push(r);
        }
        out
    }
}
