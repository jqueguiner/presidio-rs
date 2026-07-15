use std::collections::HashMap;

use presidio_anonymizer::{AnonymizerEngine, DeanonymizeEngine, OperatorConfig, RecognizerResult};
use serde_json::json;

fn one(entity: &str, start: usize, end: usize) -> Vec<RecognizerResult> {
    vec![RecognizerResult::new(entity, start, end, 0.9)]
}

#[test]
fn replace_default_uses_entity_tag() {
    let engine = AnonymizerEngine::new();
    let text = "hello John";
    let out = engine
        .anonymize(text, one("PERSON", 6, 10), &HashMap::new())
        .unwrap();
    assert_eq!(out.text, "hello <PERSON>");
}

#[test]
fn redact_removes_entity() {
    let engine = AnonymizerEngine::new();
    let mut ops = HashMap::new();
    ops.insert("PERSON".to_string(), OperatorConfig::simple("redact"));
    let out = engine
        .anonymize("hello John", one("PERSON", 6, 10), &ops)
        .unwrap();
    assert_eq!(out.text, "hello ");
}

#[test]
fn mask_from_end() {
    let engine = AnonymizerEngine::new();
    let mut ops = HashMap::new();
    ops.insert(
        "CREDIT_CARD".to_string(),
        OperatorConfig::simple("mask")
            .param("masking_char", json!("*"))
            .param("chars_to_mask", json!(12))
            .param("from_end", json!(true)),
    );
    // 16-digit number, mask last 12.
    let out = engine
        .anonymize("4095260993934932", one("CREDIT_CARD", 0, 16), &ops)
        .unwrap();
    assert_eq!(out.text, "4095************");
}

#[test]
fn hash_is_deterministic_hex() {
    let engine = AnonymizerEngine::new();
    let mut ops = HashMap::new();
    ops.insert("EMAIL_ADDRESS".to_string(), OperatorConfig::simple("hash"));
    let out = engine
        .anonymize("a@b.com", one("EMAIL_ADDRESS", 0, 7), &ops)
        .unwrap();
    assert_eq!(out.text.len(), 64); // sha256 hex
    assert!(out.text.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn encrypt_then_decrypt_roundtrip() {
    let key = "1234567890123456"; // 16 bytes
    let anon = AnonymizerEngine::new();
    let mut ops = HashMap::new();
    ops.insert(
        "PERSON".to_string(),
        OperatorConfig::simple("encrypt").param("key", json!(key)),
    );
    let anonymized = anon
        .anonymize("name: Bond", one("PERSON", 6, 10), &ops)
        .unwrap();
    assert!(!anonymized.text.contains("Bond"));

    // Deanonymize using the emitted item positions.
    let deanon = DeanonymizeEngine::new();
    let mut dops = HashMap::new();
    dops.insert(
        "PERSON".to_string(),
        OperatorConfig::simple("decrypt").param("key", json!(key)),
    );
    let restored = deanon
        .deanonymize(&anonymized.text, anonymized.items.clone(), &dops)
        .unwrap();
    assert_eq!(restored.text, "name: Bond");
}

#[test]
fn overlapping_entities_resolved_by_score() {
    let engine = AnonymizerEngine::new();
    let results = vec![
        RecognizerResult::new("A", 0, 5, 0.5),
        RecognizerResult::new("B", 2, 8, 0.9), // higher score wins the overlap
    ];
    let mut ops = HashMap::new();
    ops.insert("A".to_string(), OperatorConfig::simple("redact"));
    ops.insert("B".to_string(), OperatorConfig::simple("redact"));
    let out = engine.anonymize("0123456789", results, &ops).unwrap();
    // Only B (bytes 2..8) is applied.
    assert_eq!(out.items.len(), 1);
    assert_eq!(out.items[0].entity_type, "B");
}
