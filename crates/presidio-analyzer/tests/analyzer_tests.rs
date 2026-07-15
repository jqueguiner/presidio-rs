use presidio_analyzer::AnalyzerEngine;

fn types(text: &str) -> Vec<String> {
    let engine = AnalyzerEngine::new();
    let mut t: Vec<String> = engine
        .analyze(text, "en", None, None)
        .into_iter()
        .map(|r| r.entity_type)
        .collect();
    t.sort();
    t
}

#[test]
fn detects_valid_credit_card() {
    let engine = AnalyzerEngine::new();
    let res = engine.analyze("card 4095-2609-9393-4932", "en", None, None);
    let cc = res.iter().find(|r| r.entity_type == "CREDIT_CARD").unwrap();
    assert_eq!(cc.score, 1.0, "valid card promoted to 1.0 by Luhn");
}

#[test]
fn rejects_invalid_credit_card() {
    let engine = AnalyzerEngine::new();
    // Fails Luhn -> discarded.
    let res = engine.analyze("card 1234-5678-9012-3456", "en", None, None);
    assert!(res.iter().all(|r| r.entity_type != "CREDIT_CARD"));
}

#[test]
fn detects_email_and_ip() {
    let t = types("email me at john.doe@example.com from 192.168.0.1");
    assert!(t.contains(&"EMAIL_ADDRESS".to_string()));
    assert!(t.contains(&"IP_ADDRESS".to_string()));
}

#[test]
fn detects_valid_iban() {
    let engine = AnalyzerEngine::new();
    let res = engine.analyze("IBAN: GB82 WEST 1234 5698 7654 32", "en", None, None);
    let iban = res.iter().find(|r| r.entity_type == "IBAN_CODE").unwrap();
    assert_eq!(iban.score, 1.0);
}

#[test]
fn ssn_context_boost() {
    let engine = AnalyzerEngine::new();
    // "social security" nearby should boost the SSN score above its base 0.4.
    let with_ctx = engine
        .analyze(
            "his social security number is 078-05-1120",
            "en",
            None,
            None,
        )
        .into_iter()
        .find(|r| r.entity_type == "US_SSN")
        .unwrap();
    assert!(with_ctx.score > 0.4, "score={}", with_ctx.score);
}

#[test]
fn entity_filter_restricts_results() {
    let engine = AnalyzerEngine::new();
    let only_email = engine.analyze(
        "a@b.com and 192.168.0.1",
        "en",
        Some(&["EMAIL_ADDRESS".to_string()]),
        None,
    );
    assert!(only_email.iter().all(|r| r.entity_type == "EMAIL_ADDRESS"));
}
