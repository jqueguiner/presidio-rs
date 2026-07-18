//! End-to-end probe: OnnxNlpEngine feeds POS into a POS-gated gazetteer via AnalyzerEngine.
//! Env: PRESIDIO_POS_MODEL_DIR, ORT_DYLIB_PATH.
#[cfg(feature = "onnx-pos")]
fn main() {
    use presidio_analyzer::analyzer_engine::AnalyzerEngine;
    use presidio_analyzer::gazetteer::GazetteerRecognizer;
    use presidio_analyzer::nlp::NlpEngine;
    use presidio_analyzer::onnx_nlp::OnnxNlpEngine;
    use presidio_analyzer::registry::RecognizerRegistry;
    use std::collections::HashSet;

    let dir = std::env::var("PRESIDIO_POS_MODEL_DIR").expect("PRESIDIO_POS_MODEL_DIR");
    let onnx = OnnxNlpEngine::from_dir(&dir).expect("load model");

    let text = "Rose called Mark about Section 3 and Milk prices in London";
    println!("-- raw POS tags --");
    for t in onnx.process(text, "en").tokens {
        if !t.pos.is_empty() {
            println!("{:>10}  {}", t.text, t.pos);
        }
    }

    // A PERSON gazetteer that (wrongly) contains common-noun homographs; the POS
    // gate must keep only the PROPN uses.
    let set: HashSet<String> = ["rose", "mark", "milk", "section"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let mut reg = RecognizerRegistry::new();
    reg.add(Box::new(
        GazetteerRecognizer::new("G", "PERSON", set, 0.5).with_pos_gate(["PROPN"]),
    ));
    let engine = AnalyzerEngine::new()
        .with_registry(reg)
        .with_nlp_engine(Box::new(onnx));
    let res = engine.analyze(text, "en", Some(&["PERSON".to_string()]), None);
    println!("-- PERSON gazetteer matches after POS gate --");
    for r in &res {
        println!("  kept: {:?}  ({})", &text[r.start..r.end], r.entity_type);
    }
}
#[cfg(not(feature = "onnx-pos"))]
fn main() {}
