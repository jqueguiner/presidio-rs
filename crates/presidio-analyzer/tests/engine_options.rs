//! Tests for per-call analyze options: allow_list, ad-hoc recognizers, context.

use presidio_analyzer::{
    AllowListMatch, AnalyzeOptions, AnalyzerEngine, Pattern, PatternRecognizer,
};

#[test]
fn allow_list_exact_removes_match() {
    let engine = AnalyzerEngine::new();
    // Baseline: the email is detected.
    assert!(engine
        .analyze("mail a@b.com", "en", None, None)
        .iter()
        .any(|r| r.entity_type == "EMAIL_ADDRESS"));

    // Allow-listed -> removed.
    let opts = AnalyzeOptions {
        allow_list: vec!["a@b.com".to_string()],
        ..Default::default()
    };
    assert!(engine
        .analyze_with("mail a@b.com", "en", &opts)
        .iter()
        .all(|r| r.entity_type != "EMAIL_ADDRESS"));
}

#[test]
fn allow_list_regex_removes_match() {
    let engine = AnalyzerEngine::new();
    let opts = AnalyzeOptions {
        allow_list: vec![r"[a-z.]+@example\.com".to_string()],
        allow_list_match: AllowListMatch::Regex,
        ..Default::default()
    };
    assert!(engine
        .analyze_with("write john@example.com now", "en", &opts)
        .iter()
        .all(|r| r.entity_type != "EMAIL_ADDRESS"));
}

#[test]
fn ad_hoc_recognizer_adds_entity() {
    let engine = AnalyzerEngine::new();
    let zip = PatternRecognizer::new(
        "ZipRecognizer",
        "US_ZIP",
        vec![Pattern::new("zip", r"\b\d{5}\b", 0.4)],
    );
    let opts = AnalyzeOptions {
        entities: Some(vec!["US_ZIP".to_string()]),
        ad_hoc_recognizers: vec![&zip],
        ..Default::default()
    };
    let out = engine.analyze_with("zip 94103 here", "en", &opts);
    assert!(out.iter().any(|r| r.entity_type == "US_ZIP"));
}

#[test]
fn per_call_context_boosts_score() {
    let engine = AnalyzerEngine::new();
    // Ad-hoc recognizer whose context word ("clearance") is NOT in the text.
    let rec = PatternRecognizer::new(
        "BadgeRecognizer",
        "BADGE",
        vec![Pattern::new("badge", r"\bBX\d{4}\b", 0.3)],
    )
    .with_context(&["clearance"]);

    // Without supplemental context: no boost.
    let base = AnalyzeOptions {
        entities: Some(vec!["BADGE".to_string()]),
        ad_hoc_recognizers: vec![&rec],
        ..Default::default()
    };
    let b = engine.analyze_with("code BX1234 end", "en", &base);
    assert_eq!(
        b.iter().find(|r| r.entity_type == "BADGE").unwrap().score,
        0.3
    );

    // Supplying "clearance" as per-call context boosts it despite not being in text.
    let boosted = AnalyzeOptions {
        entities: Some(vec!["BADGE".to_string()]),
        ad_hoc_recognizers: vec![&rec],
        context: vec!["clearance".to_string()],
        ..Default::default()
    };
    let out = engine.analyze_with("code BX1234 end", "en", &boosted);
    assert!(out.iter().find(|r| r.entity_type == "BADGE").unwrap().score > 0.3);
}

#[test]
fn new_country_recognizers_via_engine() {
    let engine = AnalyzerEngine::new();
    let ents = engine.get_supported_entities("en");
    for e in [
        "ES_NIE",
        "AU_ACN",
        "AU_MEDICARE",
        "IT_VAT_CODE",
        "CA_SIN",
        "US_PASSPORT",
        "US_BANK_NUMBER",
        "IN_VOTER",
        "SG_UEN",
    ] {
        assert!(ents.contains(&e.to_string()), "missing {e}");
    }
    // A valid Canadian SIN is detected and validated to 1.0.
    let out = engine.analyze("sin 046 454 286", "en", Some(&["CA_SIN".to_string()]), None);
    assert!(out
        .iter()
        .any(|r| r.entity_type == "CA_SIN" && r.score == 1.0));
}
