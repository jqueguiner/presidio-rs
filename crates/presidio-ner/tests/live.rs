//! Live model test — downloads a ~250MB model from the HF Hub. Ignored by
//! default; run with `cargo test -p presidio-ner --test live -- --ignored`.

use presidio_analyzer::AnalyzerEngine;
use presidio_ner::TransformerNerEngine;

#[test]
#[ignore = "downloads ~250MB model from the Hugging Face Hub"]
fn detects_person_and_location() {
    let ner = TransformerNerEngine::from_pretrained("dslim/bert-base-NER")
        .expect("load dslim/bert-base-NER");
    let engine = AnalyzerEngine::new().with_nlp_engine(Box::new(ner));

    let out = engine.analyze("John Smith lives in Paris", "en", None, None);
    let types: Vec<&str> = out.iter().map(|r| r.entity_type.as_str()).collect();

    assert!(types.contains(&"PERSON"), "expected PERSON in {types:?}");
    assert!(
        types.contains(&"LOCATION"),
        "expected LOCATION in {types:?}"
    );
}
