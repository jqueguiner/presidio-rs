//! Coverage + behaviour tests for the phone and country-specific recognizers.

use presidio_analyzer::{country, AnalyzerEngine, EntityRecognizer, PhoneRecognizer};

fn phones(text: &str) -> usize {
    PhoneRecognizer::default()
        .analyze(text, &["PHONE_NUMBER".to_string()], None)
        .len()
}

#[test]
fn phone_recognizer_direct() {
    let rec = PhoneRecognizer::default();
    assert_eq!(rec.name(), "PhoneRecognizer");
    assert_eq!(rec.supported_entities(), vec!["PHONE_NUMBER".to_string()]);
    assert_eq!(rec.supported_language(), "en");
    // Entity not requested -> nothing.
    assert!(rec
        .analyze("202-555-0143", &["EMAIL_ADDRESS".to_string()], None)
        .is_empty());
}

#[test]
fn phone_accepts_real_numbers_full_region_set() {
    // US national, GB national, and international +CC numbers all detected with
    // Presidio's full default region set (US/GB/DE/FR/IL/IN/CA/BR).
    assert_eq!(phones("call 202-555-0143 now"), 1); // US
    assert_eq!(phones("ring +44 20 7946 0958"), 1); // GB international
    assert_eq!(phones("+33 6 12 34 56 78"), 1); // FR international
    assert_eq!(phones("tel 020 7946 0958"), 1); // GB national
    assert_eq!(phones("2025550143"), 1); // solid US run
}

#[test]
fn phone_leniency_rejects_non_phone_shapes() {
    // The grouping-leniency filter keeps SSNs / dates / order numbers from
    // validating as phone numbers even though permissive regions would parse
    // them. This is what makes the full region set safe.
    assert_eq!(phones("ssn 078-05-1120"), 0);
    assert_eq!(phones("date 12/05/2020"), 0);
    assert_eq!(phones("order number 12 34"), 0);
}

#[test]
fn country_validated_recognizers() {
    // Valid checksum -> promoted to 1.0.
    let ok = country::uk_nhs().analyze("943 476 5919", &["UK_NHS".to_string()], None);
    assert_eq!(ok.len(), 1);
    assert_eq!(ok[0].score, 1.0);
    // Bad checksum -> dropped.
    assert!(country::uk_nhs()
        .analyze("943 476 5918", &["UK_NHS".to_string()], None)
        .is_empty());

    assert_eq!(
        country::sg_nric().analyze("S1234567D", &["SG_NRIC_FIN".to_string()], None)[0].score,
        1.0
    );
    assert_eq!(
        country::es_nif().analyze("12345678Z", &["ES_NIF".to_string()], None)[0].score,
        1.0
    );
    assert_eq!(
        country::fi_hetu().analyze(
            "131052-308T",
            &["FI_PERSONAL_IDENTITY_CODE".to_string()],
            None
        )[0]
        .score,
        1.0
    );
    assert_eq!(
        country::au_abn().analyze("51 824 753 556", &["AU_ABN".to_string()], None)[0].score,
        1.0
    );
    assert_eq!(
        country::au_tfn().analyze("123 456 782", &["AU_TFN".to_string()], None)[0].score,
        1.0
    );
    assert_eq!(
        country::in_aadhaar().analyze("9999 4105 7058", &["IN_AADHAAR".to_string()], None)[0].score,
        1.0
    );
}

#[test]
fn country_pattern_only_recognizers() {
    assert_eq!(
        country::in_pan()
            .analyze("ABCDE1234F", &["IN_PAN".to_string()], None)
            .len(),
        1
    );
    assert_eq!(
        country::us_itin()
            .analyze("911-70-1234", &["US_ITIN".to_string()], None)
            .len(),
        1
    );
    assert_eq!(
        country::it_fiscal_code()
            .analyze("RSSMRA85T10A562S", &["IT_FISCAL_CODE".to_string()], None)
            .len(),
        1
    );
    assert_eq!(
        country::uk_nino()
            .analyze("AB123456C", &["UK_NINO".to_string()], None)
            .len(),
        1
    );
}

#[test]
fn engine_wires_country_and_phone() {
    let engine = AnalyzerEngine::new();
    let out = engine.analyze("PESEL 44051401359, call +44 20 7946 0958", "en", None, None);
    assert!(out
        .iter()
        .any(|r| r.entity_type == "PL_PESEL" && r.score == 1.0));
    assert!(out.iter().any(|r| r.entity_type == "PHONE_NUMBER"));

    // The new entity types are advertised.
    let ents = engine.get_supported_entities("en");
    for e in [
        "PHONE_NUMBER",
        "UK_NHS",
        "IN_AADHAAR",
        "AU_ABN",
        "FI_PERSONAL_IDENTITY_CODE",
    ] {
        assert!(ents.contains(&e.to_string()), "missing {e}");
    }
}
