//! Coverage-oriented tests for operators, factory, cipher and engine edge paths.

use std::collections::HashMap;

use presidio_anonymizer::aes_cipher;
use presidio_anonymizer::{
    AnonymizerEngine, Custom, DeanonymizeEngine, Decrypt, Encrypt, Hash, Keep, Mask, Operator,
    OperatorConfig, OperatorResult, OperatorType, OperatorsFactory, RecognizerResult, Redact,
    Replace,
};
use serde_json::{json, Value};

fn params(pairs: &[(&str, Value)]) -> HashMap<String, Value> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect()
}

#[test]
fn replace_variants() {
    let r = Replace;
    assert_eq!(r.operator_name(), "replace");
    assert_eq!(r.operator_type(), OperatorType::Anonymize);
    assert_eq!(
        r.operate("x", &params(&[("entity_type", json!("PERSON"))]))
            .unwrap(),
        "<PERSON>"
    );
    assert_eq!(
        r.operate(
            "x",
            &params(&[("new_value", json!("[X]")), ("entity_type", json!("P"))])
        )
        .unwrap(),
        "[X]"
    );
    // Empty new_value falls back to the entity tag.
    assert_eq!(
        r.operate(
            "x",
            &params(&[("new_value", json!("")), ("entity_type", json!("P"))])
        )
        .unwrap(),
        "<P>"
    );
    // No entity_type -> generic ENTITY.
    assert_eq!(r.operate("x", &HashMap::new()).unwrap(), "<ENTITY>");
}

#[test]
fn redact_and_keep() {
    assert_eq!(Redact.operate("abc", &HashMap::new()).unwrap(), "");
    assert_eq!(Redact.operator_name(), "redact");
    assert_eq!(Keep.operate("abc", &HashMap::new()).unwrap(), "abc");
    assert_eq!(Keep.operator_name(), "keep");
    assert_eq!(Keep.operator_type(), OperatorType::Anonymize);
}

#[test]
fn mask_paths() {
    let m = Mask;
    assert_eq!(m.operator_name(), "mask");
    // default chars_to_mask = whole string
    assert_eq!(
        m.operate("abcd", &params(&[("masking_char", json!("*"))]))
            .unwrap(),
        "****"
    );
    // mask first two from the front
    assert_eq!(
        m.operate(
            "abcd",
            &params(&[
                ("masking_char", json!("#")),
                ("chars_to_mask", json!(2)),
                ("from_end", json!(false))
            ])
        )
        .unwrap(),
        "##cd"
    );
    // validate errors
    assert!(m
        .validate(&params(&[("masking_char", json!("ab"))]))
        .is_err());
    assert!(m
        .validate(&params(&[("chars_to_mask", json!(-1))]))
        .is_err());
    assert!(m
        .validate(&params(&[
            ("masking_char", json!("*")),
            ("chars_to_mask", json!(3))
        ]))
        .is_ok());
}

#[test]
fn hash_paths() {
    let h = Hash;
    assert_eq!(h.operator_name(), "hash");
    assert_eq!(h.operate("x", &HashMap::new()).unwrap().len(), 64); // sha256
    assert_eq!(
        h.operate("x", &params(&[("hash_type", json!("sha512"))]))
            .unwrap()
            .len(),
        128
    );
    assert!(h.validate(&params(&[("hash_type", json!("md5"))])).is_err());
    assert!(h
        .validate(&params(&[("hash_type", json!("sha256"))]))
        .is_ok());
}

#[test]
fn encrypt_decrypt_operator() {
    let e = Encrypt;
    let d = Decrypt;
    assert_eq!(e.operator_name(), "encrypt");
    assert_eq!(d.operator_name(), "decrypt");
    assert_eq!(e.operator_type(), OperatorType::Anonymize);
    assert_eq!(d.operator_type(), OperatorType::Deanonymize);

    assert!(e.validate(&HashMap::new()).is_err()); // missing key
    assert!(e.validate(&params(&[("key", json!("short"))])).is_err()); // bad length
    assert!(e
        .validate(&params(&[("key", json!("1234567890123456"))]))
        .is_ok());
    assert!(d.validate(&HashMap::new()).is_err());
    assert!(d
        .validate(&params(&[("key", json!("1234567890123456"))]))
        .is_ok());

    let key = json!("1234567890123456");
    let enc = e
        .operate("secret", &params(&[("key", key.clone())]))
        .unwrap();
    assert_eq!(d.operate(&enc, &params(&[("key", key)])).unwrap(), "secret");

    assert!(e.operate("x", &HashMap::new()).is_err());
    assert!(d.operate("x", &HashMap::new()).is_err());
}

#[test]
fn custom_operator() {
    let c = Custom::new("upper", OperatorType::Anonymize, |s| s.to_uppercase());
    assert_eq!(c.operator_name(), "upper");
    assert_eq!(c.operator_type(), OperatorType::Anonymize);
    assert_eq!(c.operate("ab", &HashMap::new()).unwrap(), "AB");
}

#[test]
fn aes_cipher_edges() {
    assert!(aes_cipher::is_valid_key_size(16));
    assert!(aes_cipher::is_valid_key_size(24));
    assert!(aes_cipher::is_valid_key_size(32));
    assert!(!aes_cipher::is_valid_key_size(10));

    // 192-bit roundtrip.
    let k24 = b"123456789012345678901234";
    let enc = aes_cipher::encrypt(k24, "hi").unwrap();
    assert_eq!(aes_cipher::decrypt(k24, &enc).unwrap(), "hi");

    assert!(aes_cipher::decrypt(b"1234567890123456", "AAAA").is_err()); // too short
    assert!(aes_cipher::decrypt(b"1234567890123456", "*bad*").is_err()); // invalid base64
    assert!(aes_cipher::decrypt(b"short", &enc).is_err()); // invalid key length
    assert!(aes_cipher::encrypt(b"short", "x").is_err()); // invalid key length
}

#[test]
fn factory_paths() {
    let f = OperatorsFactory::default();
    assert!(f.get("replace", OperatorType::Anonymize).is_some());
    assert!(f.get("decrypt", OperatorType::Deanonymize).is_some());
    assert!(f.get("nope", OperatorType::Anonymize).is_none());
    assert!(f
        .operator_names(OperatorType::Anonymize)
        .contains(&"replace".to_string()));
    assert!(f
        .operator_names(OperatorType::Deanonymize)
        .contains(&"decrypt".to_string()));

    let mut f2 = OperatorsFactory::new();
    f2.add(Box::new(Custom::new("rev", OperatorType::Anonymize, |s| {
        s.chars().rev().collect()
    })));
    assert!(f2.get("rev", OperatorType::Anonymize).is_some());
}

#[test]
fn entities_helpers() {
    let a = RecognizerResult::new("A", 0, 5, 0.5);
    let b = RecognizerResult::new("A", 1, 3, 0.5);
    assert_eq!(a.len(), 5);
    assert!(!a.is_empty());
    assert!(a.contains(&b));
    assert!(a.intersects(&b));
    assert!(RecognizerResult::new("A", 2, 2, 0.0).is_empty());

    let cfg = OperatorConfig::new("mask", HashMap::new()).param("masking_char", json!("#"));
    assert_eq!(cfg.operator_name, "mask");
    assert!(cfg.params.contains_key("masking_char"));
    assert!(OperatorConfig::simple("redact").params.is_empty());
}

#[test]
fn operator_result_carries_score() {
    let eng = AnonymizerEngine::default();
    let out = eng
        .anonymize(
            "hi bob",
            vec![RecognizerResult::new("PERSON", 3, 6, 0.87)],
            &HashMap::new(),
        )
        .unwrap();
    // Detection score preserved on the operator result (issue #2057).
    assert_eq!(out.items[0].score, Some(0.87));
    // Serialized into JSON.
    let json = serde_json::to_string(&out.items[0]).unwrap();
    assert!(json.contains("\"score\":0.87"), "json was: {json}");

    // A result built without a score omits the field entirely (backward compat).
    let bare = OperatorResult {
        start: 0,
        end: 1,
        entity_type: "X".to_string(),
        text: "*".to_string(),
        operator: "replace".to_string(),
        score: None,
    };
    assert!(!serde_json::to_string(&bare).unwrap().contains("score"));
}

#[test]
fn engine_fallbacks_and_errors() {
    let eng = AnonymizerEngine::default();

    // Unknown operator -> error.
    let mut ops = HashMap::new();
    ops.insert("X".to_string(), OperatorConfig::simple("bogus"));
    assert!(eng
        .anonymize("hello", vec![RecognizerResult::new("X", 0, 5, 0.9)], &ops)
        .is_err());

    // DEFAULT config applies to any entity.
    let mut ops2 = HashMap::new();
    ops2.insert("DEFAULT".to_string(), OperatorConfig::simple("redact"));
    let out = eng
        .anonymize(
            "hi bob",
            vec![RecognizerResult::new("PERSON", 3, 6, 0.9)],
            &ops2,
        )
        .unwrap();
    assert_eq!(out.text, "hi ");

    // No config at all -> replace fallback.
    let out2 = eng
        .anonymize(
            "hi bob",
            vec![RecognizerResult::new("PERSON", 3, 6, 0.9)],
            &HashMap::new(),
        )
        .unwrap();
    assert_eq!(out2.text, "hi <PERSON>");

    // Register a custom operator on the engine factory.
    let mut eng2 = AnonymizerEngine::new();
    eng2.factory_mut().add(Box::new(Custom::new(
        "star",
        OperatorType::Anonymize,
        |_| "***".into(),
    )));
    let mut ops3 = HashMap::new();
    ops3.insert("DEFAULT".to_string(), OperatorConfig::simple("star"));
    let o3 = eng2
        .anonymize("hi bob", vec![RecognizerResult::new("X", 3, 6, 0.9)], &ops3)
        .unwrap();
    assert_eq!(o3.text, "hi ***");
}

#[test]
fn deanonymize_paths() {
    let de = DeanonymizeEngine::default();
    let mut dops = HashMap::new();
    dops.insert("X".to_string(), OperatorConfig::simple("bogus"));
    let item = OperatorResult {
        start: 0,
        end: 3,
        entity_type: "X".to_string(),
        text: "abc".to_string(),
        operator: "x".to_string(),
        score: None,
    };
    assert!(de.deanonymize("abc", vec![item], &dops).is_err());

    let mut de2 = DeanonymizeEngine::new();
    de2.factory_mut().add(Box::new(Custom::new(
        "id",
        OperatorType::Deanonymize,
        |s| s.to_string(),
    )));
    let mut dops2 = HashMap::new();
    dops2.insert("DEFAULT".to_string(), OperatorConfig::simple("id"));
    let item2 = OperatorResult {
        start: 0,
        end: 3,
        entity_type: "A".to_string(),
        text: "xyz".to_string(),
        operator: "e".to_string(),
        score: None,
    };
    let r = de2.deanonymize("xyz", vec![item2], &dops2).unwrap();
    assert_eq!(r.text, "xyz");
}
