//! Language-agnostic pattern detection works for any language code.

use presidio_analyzer::AnalyzerEngine;

#[test]
fn pattern_pii_detected_in_any_language() {
    let engine = AnalyzerEngine::new();
    let out = engine.analyze(
        "carte 4095-2609-9393-4932, courriel a@b.fr",
        "fr",
        None,
        None,
    );
    let types: Vec<&str> = out.iter().map(|r| r.entity_type.as_str()).collect();
    assert!(types.contains(&"CREDIT_CARD"), "{types:?}");
    assert!(types.contains(&"EMAIL_ADDRESS"), "{types:?}");
}

#[test]
fn supported_entities_per_language() {
    let engine = AnalyzerEngine::new();
    let fr = engine.get_supported_entities("fr");
    assert!(fr.contains(&"CREDIT_CARD".to_string())); // agnostic -> any language
    assert!(fr.contains(&"BR_CPF".to_string()));
    assert!(!fr.contains(&"PERSON".to_string())); // NER is en-only, not agnostic

    let en = engine.get_supported_entities("en");
    assert!(en.contains(&"PERSON".to_string())); // en keeps NER entities
}
