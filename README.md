# presidio-rust

A Rust port of [Microsoft Presidio](https://github.com/data-privacy-stack/presidio) —
PII **detection** (`presidio-analyzer`) and **anonymization** (`presidio-anonymizer`).

It mirrors Presidio's architecture and public concepts (recognizers, registry,
analyzer engine, operators, anonymizer/deanonymizer engines) in idiomatic,
dependency-light Rust. Checksum validators (Luhn, IBAN mod-97, Base58Check) and
context-aware score enhancement are ported faithfully. The NLP/NER layer is a
pluggable trait so a real transformer backend can be dropped in without touching
the recognizers.

## Workspace layout

```
crates/
  presidio-analyzer/     # PII detection  (port of presidio-analyzer)
  presidio-anonymizer/   # (de)anonymization (port of presidio-anonymizer)
  presidio-cli/          # `presidio` binary tying the two together
```

## Quick start

```bash
cargo build --release

# List detectable entity types
./target/release/presidio entities

# Detect PII (JSON with per-result explanation)
./target/release/presidio analyze --text "call 212-555-0143, ssn 078-05-1120"

# Anonymize
./target/release/presidio anonymize --text "card 4095-2609-9393-4932" --operator mask --masking-char '#'
```

### Library

```rust
use presidio_analyzer::AnalyzerEngine;
use presidio_anonymizer::{AnonymizerEngine, OperatorConfig, RecognizerResult};
use std::collections::HashMap;

let analyzer = AnalyzerEngine::new();
let text = "my email is jane@acme.io";
let found = analyzer.analyze(text, "en", None, None);

let anon = AnonymizerEngine::new();
let spans: Vec<RecognizerResult> = found.iter()
    .map(|r| RecognizerResult::new(r.entity_type.clone(), r.start, r.end, r.score))
    .collect();
let mut ops = HashMap::new();
ops.insert("EMAIL_ADDRESS".into(), OperatorConfig::simple("redact"));
let result = anon.anonymize(text, spans, &ops).unwrap();
```

## Mapping to upstream Presidio

| Presidio (Python)                         | presidio-rust (Rust)                              |
|-------------------------------------------|---------------------------------------------------|
| `Pattern`, `PatternRecognizer`            | `pattern::Pattern`, `recognizer::PatternRecognizer` |
| `EntityRecognizer`                        | `recognizer::EntityRecognizer` (trait)            |
| `RecognizerRegistry`                      | `registry::RecognizerRegistry`                    |
| `AnalyzerEngine`                          | `analyzer_engine::AnalyzerEngine`                 |
| `NlpEngine` / spaCy / transformers        | `nlp::NlpEngine` (trait) + `SimpleNlpEngine`      |
| `SpacyRecognizer` (NER → results)         | `ner_recognizer::NerRecognizer`                   |
| `LemmaContextAwareEnhancer`               | `context::LemmaContextAwareEnhancer`              |
| `RecognizerResult` / `AnalysisExplanation`| `entities::{RecognizerResult, AnalysisExplanation}` |
| operators (replace/redact/mask/hash/…)    | `operators::{Replace,Redact,Mask,Hash,Keep,Encrypt,Decrypt,Custom}` |
| `AESCipher`                               | `aes_cipher` (AES-CBC, IV‖ct, base64)             |
| `OperatorsFactory`                        | `factory::OperatorsFactory`                       |
| `AnonymizerEngine` / `DeanonymizeEngine`  | `engine::AnonymizerEngine` / `deanonymize::DeanonymizeEngine` |

### Predefined recognizers ported

**Generic:** `CREDIT_CARD` (Luhn), `CRYPTO` (BTC Base58Check), `IBAN_CODE`
(mod-97), `EMAIL_ADDRESS`, `IP_ADDRESS` (v4/v6), `MAC_ADDRESS`, `URL`,
`DATE_TIME`, `US_SSN`.

**Phone:** `PHONE_NUMBER` via the [`phonenumber`](https://crates.io/crates/phonenumber)
crate (Rust libphonenumber) — parses + validates, default regions US/GB, and any
`+CC` international number regardless of region. `PhoneRecognizer.regions` is
configurable.

**Country-specific** (checksum-validated → promoted to 1.0): `UK_NHS` (mod-11),
`ES_NIF`, `PL_PESEL`, `SG_NRIC_FIN`, `AU_ABN` (mod-89), `AU_TFN`, `IN_AADHAAR`
(Verhoeff), `FI_PERSONAL_IDENTITY_CODE`. **Pattern-only:** `UK_NINO`, `IN_PAN`,
`IT_FISCAL_CODE`, `US_ITIN`.

**NER** entities (`PERSON`, `LOCATION`, `ORGANIZATION`, `NRP`) are wired through
`NerRecognizer` and activate once an NLP engine with NER is set.

### Operators ported

`replace`, `redact`, `mask`, `hash` (sha256/sha512), `keep`, `encrypt`,
`decrypt`, `custom`.

## Extending

**Add a recognizer** — build a `PatternRecognizer` (optionally with a checksum
`Validator`) and register it:

```rust
use presidio_analyzer::{AnalyzerEngine, Pattern, PatternRecognizer, RecognizerRegistry};

let mut registry = RecognizerRegistry::with_predefined("en");
registry.add(Box::new(
    PatternRecognizer::new("ZipRecognizer", "US_ZIP",
        vec![Pattern::new("zip", r"\b\d{5}(?:-\d{4})?\b", 0.3)])
        .with_context(&["zip", "postal"]),
));
let engine = AnalyzerEngine::new().with_registry(registry);
```

**Add real NER** — implement `nlp::NlpEngine` (e.g. over `rust-bert` / ONNX),
populate `NlpArtifacts::entities`, and pass it via
`AnalyzerEngine::new().with_nlp_engine(Box::new(MyEngine))`. The existing
`NerRecognizer` maps model labels onto Presidio entity names.

**Add a custom operator** — register an `operators::Custom` (or any `Operator`)
on the engine's factory via `factory_mut()`.

## Port status

Ported and tested:
- Pattern-recognizer framework, registry, analyzer-engine orchestration
- Checksum validation (Luhn / IBAN mod-97 / Base58Check / NHS / PESEL / SG NRIC /
  AU ABN+TFN / Aadhaar Verhoeff / FI HETU) and result promotion
- `PHONE_NUMBER` via real libphonenumber (`phonenumber` crate)
- Lemma context-aware score enhancement
- Conflict resolution (highest score, longest span, non-overlapping)
- Full anonymizer/deanonymizer operator set incl. AES-CBC encrypt/decrypt

Simplified vs. upstream (contributions welcome):
- **NER** — trait seam in place; no bundled model (upstream bundles spaCy). This
  is the main behavioural gap: `PERSON`/`LOCATION`/`ORGANIZATION` need an NLP
  backend (e.g. `rust-bert`/ONNX) wired via `with_nlp_engine`.
- **DATE_TIME** — regex-based; upstream also uses a date NER.
- **Country-specific recognizers** — a representative, checksum-validated subset
  is in; the full 18-country set under `predefined_recognizers/country_specific`
  is not yet exhaustive.
- **presidio-image-redactor** / **presidio-structured** — not yet ported.

## Testing

```bash
cargo test        # unit + integration + doctests
```
