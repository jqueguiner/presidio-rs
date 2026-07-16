//! Engine-level detection for the international recognizers.

use presidio_analyzer::AnalyzerEngine;

#[test]
fn engine_advertises_new_entities() {
    let ents = AnalyzerEngine::new().get_supported_entities("en");
    for e in [
        "BR_CPF",
        "BR_CNPJ",
        "NL_BSN",
        "TR_TCKN",
        "BE_NRN",
        "PT_NIF",
        "CN_RIC",
        "RU_SNILS",
        "DE_TAX_ID",
        "SE_PERSONNUMMER",
        "ZA_ID",
        "KR_RRN",
        "JP_MYNUMBER",
        "MX_RFC",
        "MX_CURP",
    ] {
        assert!(ents.contains(&e.to_string()), "missing {e}");
    }
}

#[test]
fn detects_and_validates_intl_ids() {
    let engine = AnalyzerEngine::new();

    let cpf = engine.analyze(
        "CPF 111.444.777-35",
        "en",
        Some(&["BR_CPF".to_string()]),
        None,
    );
    assert!(cpf
        .iter()
        .any(|r| r.entity_type == "BR_CPF" && r.score == 1.0));

    let za = engine.analyze("ID 8001015009087", "en", Some(&["ZA_ID".to_string()]), None);
    assert!(za
        .iter()
        .any(|r| r.entity_type == "ZA_ID" && r.score == 1.0));

    // Invalid checksum -> dropped, not surfaced as that entity.
    let bad = engine.analyze(
        "CPF 111.444.777-36",
        "en",
        Some(&["BR_CPF".to_string()]),
        None,
    );
    assert!(bad.iter().all(|r| r.entity_type != "BR_CPF"));
}
