//! Per-language NLP/NER routing.

use presidio_analyzer::nlp::{NerEntity, NlpArtifacts, NlpEngine};
use presidio_analyzer::AnalyzerEngine;

struct FrNer;
impl NlpEngine for FrNer {
    fn process(&self, _text: &str, language: &str) -> NlpArtifacts {
        NlpArtifacts {
            tokens: vec![],
            entities: vec![NerEntity {
                entity_type: "PER".into(),
                start: 0,
                end: 6,
                score: 0.95,
            }],
            language: language.to_string(),
        }
    }
}

#[test]
fn routes_ner_by_language() {
    let engine = AnalyzerEngine::new().with_nlp_engine_for("fr", Box::new(FrNer));

    // "fr" -> the French engine emits PER -> PERSON.
    let fr = engine.analyze(
        "Pierre habite ici",
        "fr",
        Some(&["PERSON".to_string()]),
        None,
    );
    assert!(fr.iter().any(|r| r.entity_type == "PERSON"), "{fr:?}");

    // "en" -> falls back to the default engine (no NER) -> no PERSON.
    let en = engine.analyze(
        "Pierre lives here",
        "en",
        Some(&["PERSON".to_string()]),
        None,
    );
    assert!(en.iter().all(|r| r.entity_type != "PERSON"));
}
