//! Tests for the local `surrogate` operator.

use std::collections::HashMap;

use presidio_anonymizer::{
    AnonymizerEngine, Operator, OperatorConfig, OperatorType, RecognizerResult, Surrogate,
};
use serde_json::{json, Value};

fn params(entity: &str) -> HashMap<String, Value> {
    let mut m = HashMap::new();
    m.insert("entity_type".to_string(), json!(entity));
    m
}

fn luhn(s: &str) -> bool {
    let ds: Vec<u32> = s.chars().filter_map(|c| c.to_digit(10)).collect();
    let parity = ds.len() % 2;
    let mut sum = 0;
    for (i, &d) in ds.iter().enumerate() {
        let mut v = d;
        if i % 2 == parity {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
    }
    sum % 10 == 0
}

#[test]
fn surrogate_basics_and_determinism() {
    let s = Surrogate;
    assert_eq!(s.operator_name(), "surrogate");
    assert_eq!(s.operator_type(), OperatorType::Anonymize);

    // Deterministic: same input -> same surrogate.
    let a = s.operate("John Smith", &params("PERSON")).unwrap();
    let b = s.operate("John Smith", &params("PERSON")).unwrap();
    assert_eq!(a, b);
    assert_eq!(a.split_whitespace().count(), 2, "person = two words: {a}");

    // Different source text -> (very likely) different surrogate.
    let c = s.operate("Jane Doe", &params("PERSON")).unwrap();
    assert_ne!(a, c);

    // Unknown entity type -> generic tag.
    assert_eq!(s.operate("x", &params("FOO")).unwrap(), "<FOO>");
}

#[test]
fn surrogate_formats_by_type() {
    let s = Surrogate;
    let email = s.operate("a@b.com", &params("EMAIL_ADDRESS")).unwrap();
    assert!(email.contains('@') && email.ends_with("example.com"));

    let ssn = s.operate("078-05-1120", &params("US_SSN")).unwrap();
    assert_eq!(ssn.len(), 11); // NNN-NN-NNNN

    let ip = s.operate("192.168.0.1", &params("IP_ADDRESS")).unwrap();
    assert_eq!(ip.split('.').count(), 4);

    let cc = s
        .operate("4095-2609-9393-4932", &params("CREDIT_CARD"))
        .unwrap();
    assert_eq!(cc.len(), 16);
    assert!(cc.chars().all(|c| c.is_ascii_digit()));
    assert!(luhn(&cc), "surrogate card must be Luhn-valid: {cc}");

    assert!(s
        .operate("x", &params("PHONE_NUMBER"))
        .unwrap()
        .starts_with("+1 ("));
    assert!(!s.operate("x", &params("LOCATION")).unwrap().is_empty());
    assert!(!s.operate("x", &params("ORGANIZATION")).unwrap().is_empty());
    assert!(!s.operate("x", &params("NRP")).unwrap().is_empty());
    assert_eq!(s.operate("x", &params("DATE_TIME")).unwrap().len(), 10); // YYYY-MM-DD
}

#[test]
fn surrogate_via_engine() {
    let engine = AnonymizerEngine::new();
    let mut ops = HashMap::new();
    ops.insert("DEFAULT".to_string(), OperatorConfig::simple("surrogate"));
    let out = engine
        .anonymize(
            "hi bob",
            vec![RecognizerResult::new("PERSON", 3, 6, 0.9)],
            &ops,
        )
        .unwrap();
    assert!(out.text.starts_with("hi "));
    assert!(!out.text.contains("bob"));
}
