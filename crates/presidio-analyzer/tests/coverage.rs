//! Coverage-oriented tests exercising internal paths not hit by the
//! behavioural integration tests.

use presidio_analyzer::context::LemmaContextAwareEnhancer;
use presidio_analyzer::nlp::{NerEntity, NlpArtifacts, NlpEngine};
use presidio_analyzer::{
    predefined, AnalysisExplanation, AnalyzerEngine, EntityRecognizer, NerRecognizer, Pattern,
    PatternRecognizer, RecognizerRegistry, RecognizerResult, SimpleNlpEngine, MAX_SCORE, MIN_SCORE,
};

#[test]
fn recognizer_result_helpers() {
    let a = RecognizerResult::new("X", 0, 5, 0.5);
    let b = RecognizerResult::new("X", 2, 4, 0.5);
    assert_eq!(a.len(), 5);
    assert!(!a.is_empty());
    assert!(a.contains(&b));
    assert!(a.intersects(&b));
    assert!(!a.same_span(&b));
    assert!(RecognizerResult::new("X", 3, 3, 0.0).is_empty());
    assert_eq!(MAX_SCORE, 1.0);
    assert_eq!(MIN_SCORE, 0.0);
}

#[test]
fn deny_list_recognizer() {
    let rec =
        PatternRecognizer::new("Titles", "TITLE", vec![]).with_deny_list(&["ceo", "cto"], 0.8);
    let res = rec.analyze("our CEO and CTO", &["TITLE".to_string()], None);
    assert_eq!(res.len(), 2);
    assert!(res
        .iter()
        .all(|r| r.entity_type == "TITLE" && (r.score - 0.8).abs() < 1e-9));
    // Not-requested entity -> nothing.
    assert!(rec.analyze("CEO", &["OTHER".to_string()], None).is_empty());
    assert_eq!(rec.name(), "Titles");
    assert_eq!(rec.supported_entities(), vec!["TITLE".to_string()]);
    assert_eq!(rec.supported_language(), "en");
}

#[test]
fn validator_rejects_and_keeps() {
    let ssn = predefined::us_ssn();
    // area 000 is structurally invalid -> dropped.
    assert!(ssn
        .analyze("000-12-3456", &["US_SSN".to_string()], None)
        .is_empty());
    // Plausible SSN -> kept at base score (validator returns None).
    let ok = ssn.analyze("123-45-6789", &["US_SSN".to_string()], None);
    assert_eq!(ok.len(), 1);
    assert!((ok[0].score - 0.4).abs() < 1e-9);
}

#[test]
fn remove_contained_dominated_and_exact_dup() {
    // Longer, higher-scoring match dominates the contained shorter ones.
    let rec = PatternRecognizer::new(
        "Multi",
        "NUM",
        vec![
            Pattern::new("four", r"\d{4}", 0.9),
            Pattern::new("two", r"\d{2}", 0.3),
        ],
    );
    let res = rec.analyze("1234", &["NUM".to_string()], None);
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].len(), 4);

    // Two patterns matching the exact same span -> deduplicated.
    let rec2 = PatternRecognizer::new(
        "Dup",
        "NUM",
        vec![
            Pattern::new("a", r"\d{4}", 0.5),
            Pattern::new("b", r"[0-9]{4}", 0.5),
        ],
    );
    assert_eq!(rec2.analyze("1234", &["NUM".to_string()], None).len(), 1);
}

struct FakeNer;
impl NlpEngine for FakeNer {
    fn process(&self, _text: &str, language: &str) -> NlpArtifacts {
        NlpArtifacts {
            tokens: vec![],
            entities: vec![
                NerEntity {
                    entity_type: "PER".into(),
                    start: 0,
                    end: 4,
                    score: 0.85,
                },
                NerEntity {
                    entity_type: "UNMAPPED".into(),
                    start: 5,
                    end: 8,
                    score: 0.9,
                },
            ],
            language: language.to_string(),
        }
    }
}

#[test]
fn ner_recognizer_via_custom_engine() {
    let engine = AnalyzerEngine::new().with_nlp_engine(Box::new(FakeNer));
    let res = engine.analyze(
        "Bond xyz likes cars",
        "en",
        Some(&["PERSON".to_string()]),
        None,
    );
    assert!(res.iter().any(|r| r.entity_type == "PERSON"));

    // Direct NerRecognizer paths: no nlp, unmapped label, not-requested entity.
    let ner = NerRecognizer::default();
    assert_eq!(ner.name(), "NerRecognizer");
    assert_eq!(ner.supported_language(), "en");
    assert!(ner.supported_entities().contains(&"PERSON".to_string()));
    assert!(ner.analyze("x", &["PERSON".to_string()], None).is_empty());

    let art = NlpArtifacts {
        tokens: vec![],
        entities: vec![
            NerEntity {
                entity_type: "UNMAPPED".into(),
                start: 0,
                end: 1,
                score: 0.5,
            },
            NerEntity {
                entity_type: "PER".into(),
                start: 0,
                end: 1,
                score: 0.5,
            },
        ],
        language: "en".into(),
    };
    // PER maps to PERSON but only LOCATION requested -> empty.
    assert!(ner
        .analyze("x", &["LOCATION".to_string()], Some(&art))
        .is_empty());
    // PERSON requested -> one result.
    assert_eq!(
        ner.analyze("x", &["PERSON".to_string()], Some(&art)).len(),
        1
    );
}

#[test]
fn registry_paths() {
    // Non-English predefined load is a no-op.
    let empty = RecognizerRegistry::with_predefined("fr");
    assert!(empty.supported_entities("fr").is_empty());

    let mut reg = RecognizerRegistry::default();
    reg.add(Box::new(predefined::email()));
    assert_eq!(
        reg.supported_entities("en"),
        vec!["EMAIL_ADDRESS".to_string()]
    );
    assert_eq!(
        reg.get_recognizers("en", &["EMAIL_ADDRESS".to_string()])
            .len(),
        1
    );
    assert!(reg
        .get_recognizers("en", &["PHONE_NUMBER".to_string()])
        .is_empty());
}

#[test]
fn engine_threshold_registry_and_conflict() {
    let engine = AnalyzerEngine::default();
    assert!(engine
        .get_supported_entities("en")
        .contains(&"EMAIL_ADDRESS".to_string()));

    // A high threshold drops the medium-confidence email.
    let high = engine.analyze("a@b.com", "en", None, Some(0.99));
    assert!(high.iter().all(|r| r.score >= 0.99));

    // Overlapping results across recognizers: higher score wins.
    let mut reg = RecognizerRegistry::new();
    reg.add(Box::new(predefined::email())); // EMAIL_ADDRESS @ 0.5
    reg.add(Box::new(PatternRecognizer::new(
        "Dup",
        "DUP",
        vec![Pattern::new("p", r"\ba@b\.com\b", 0.9)],
    )));
    let e2 = AnalyzerEngine::new().with_registry(reg);
    let res = e2.analyze("a@b.com", "en", None, None);
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].entity_type, "DUP");
}

#[test]
fn simple_nlp_tokenizes() {
    let nlp = SimpleNlpEngine::default();
    let art = nlp.process("the quick brown_fox", "en");
    assert!(art.tokens.iter().any(|t| t.lemma == "the" && t.is_stop));
    assert!(art.tokens.iter().any(|t| t.text == "brown_fox")); // trailing token, underscore kept
    assert_eq!(art.language, "en");
    assert!(art.entities.is_empty());
}

#[test]
fn context_enhancer_suffix_and_floor() {
    // suffix window + normal boost
    let enh = LemmaContextAwareEnhancer {
        context_similarity_factor: 0.35,
        min_score_with_context: 0.4,
        prefix_count: 0,
        suffix_count: 3,
    };
    let nlp = SimpleNlpEngine::new().process("1234 card", "en");
    let mut results = vec![{
        let mut r = RecognizerResult::new("CREDIT_CARD", 0, 4, 0.3);
        r.context = vec!["card".to_string()];
        r.analysis_explanation = Some(AnalysisExplanation::default());
        r
    }];
    enh.enhance(&mut results, &nlp, &[]);
    assert!(results[0].score > 0.3);

    // score 0.0 + context -> floored to min_score_with_context (0.4)
    let enh2 = LemmaContextAwareEnhancer::default();
    let nlp2 = SimpleNlpEngine::new().process("ssn 000", "en");
    let mut r2 = vec![{
        let mut r = RecognizerResult::new("US_SSN", 4, 7, 0.0);
        r.context = vec!["ssn".to_string()];
        r.analysis_explanation = Some(AnalysisExplanation::default());
        r
    }];
    enh2.enhance(&mut r2, &nlp2, &[]);
    assert!((r2[0].score - 0.4).abs() < 1e-9);
}

#[test]
fn imei_and_vin_detected_end_to_end() {
    let engine = AnalyzerEngine::default();

    // Valid IMEI (Luhn) promoted to 1.0.
    let imei = engine.analyze("device imei 49-015420-323751-8", "en", None, None);
    let hit = imei.iter().find(|r| r.entity_type == "IMEI").unwrap();
    assert!((hit.score - 1.0).abs() < 1e-9);
    // Bad Luhn -> dropped.
    assert!(engine
        .analyze("imei 490154203237519", "en", None, None)
        .iter()
        .all(|r| r.entity_type != "IMEI"));

    // Valid North-American VIN promoted to 1.0.
    let vin = engine.analyze("vin 1M8GDM9AXKP042788", "en", None, None);
    let hit = vin.iter().find(|r| r.entity_type == "VIN").unwrap();
    assert!((hit.score - 1.0).abs() < 1e-9);
    // Bad NA check digit -> dropped.
    assert!(engine
        .analyze("vin 1M8GDM9A0KP042788", "en", None, None)
        .iter()
        .all(|r| r.entity_type != "VIN"));
}

#[test]
fn batch_country_recognizers_end_to_end() {
    let engine = AnalyzerEngine::default();
    let ents = engine.get_supported_entities("en");
    for e in [
        "TW_NATIONAL_ID",
        "CZ_BIRTH_NUMBER",
        "CA_POSTAL_CODE",
        "ZA_COMPANY_REGISTRATION",
        "ZA_VAT_NUMBER",
    ] {
        assert!(ents.contains(&e.to_string()), "missing {e}");
    }

    // TW national ID: valid checksum promoted to 1.0; bad checksum dropped.
    let tw = engine.analyze("id number A123456789", "en", None, None);
    let hit = tw
        .iter()
        .find(|r| r.entity_type == "TW_NATIONAL_ID")
        .unwrap();
    assert!((hit.score - 1.0).abs() < 1e-9);
    assert!(engine
        .analyze("id number A123456788", "en", None, None)
        .iter()
        .all(|r| r.entity_type != "TW_NATIONAL_ID"));

    // CZ birth number: mod-11 valid -> 1.0.
    let cz = engine.analyze("rodné číslo 780123/2340", "en", None, None);
    let hit = cz
        .iter()
        .find(|r| r.entity_type == "CZ_BIRTH_NUMBER")
        .unwrap();
    assert!((hit.score - 1.0).abs() < 1e-9);

    // CA postal code: canonical + space-omitted, case-insensitive.
    assert!(engine
        .analyze("postal code K1A 0B1", "en", None, None)
        .iter()
        .any(|r| r.entity_type == "CA_POSTAL_CODE"));
    assert!(engine
        .analyze("mailing k1a0b1", "en", None, None)
        .iter()
        .any(|r| r.entity_type == "CA_POSTAL_CODE"));

    // ZA company registration: distinctive slash format.
    assert!(engine
        .analyze("cipc 2019/123456/07", "en", None, None)
        .iter()
        .any(|r| r.entity_type == "ZA_COMPANY_REGISTRATION"));
}

#[test]
fn validators_edge_cases() {
    use presidio_analyzer::validators::*;
    assert_eq!(validate_us_ssn("123-45-6789"), None);
    assert_eq!(validate_us_ssn("12345"), Some(false));
    assert_eq!(validate_us_ssn("078-05-0000"), Some(false)); // serial 0000
    assert_eq!(validate_credit_card("41111"), Some(false)); // too short
    assert_eq!(validate_iban("US1234"), Some(false)); // too short
    assert_eq!(validate_btc("0OIl"), Some(false)); // invalid base58 chars
    assert!(luhn_valid("4111111111111111"));
}
