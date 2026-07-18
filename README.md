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
  presidio-server/       # HTTP service (Presidio-style REST API)
  presidio-ner/          # optional Candle NER backend (heavy; opt-in)
```

## HTTP server

```bash
PORT=8080 cargo run -p presidio-server           # or: docker build -f crates/presidio-server/Dockerfile -t presidio-server . && docker run -p 8080:8080 presidio-server
curl -s localhost:8080/analyze -H 'content-type: application/json' \
  -d '{"text":"mail a@b.com, ssn 078-05-1120"}'
curl -s localhost:8080/anonymize_text -H 'content-type: application/json' \
  -d '{"text":"mail a@b.com","operator":"redact"}'
```
Endpoints: `GET /health`, `GET /supportedentities?language=en`, `POST /analyze`,
`POST /anonymize` (Presidio-shaped `{text, analyzer_results, anonymizers}`),
`POST /anonymize_text` (analyze + anonymize in one call).

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
`DATE_TIME`, `IMEI` (Luhn), `VIN` (ISO 3779 mod-11), `US_SSN`.

**Phone:** `PHONE_NUMBER` via the [`phonenumber`](https://crates.io/crates/phonenumber)
crate (Rust libphonenumber). Runs Presidio's full default region set
(`US/GB/DE/FR/IL/IN/CA/BR`) and emulates libphonenumber's `Leniency.VALID`
grouping check so SSNs/dates don't validate as phone numbers in permissive
regions. `+CC` international numbers are detected regardless of region.
`PhoneRecognizer.regions` is configurable.

**Country-specific** (checksum-validated → promoted to 1.0): `UK_NHS` (mod-11),
`ES_NIF`, `ES_NIE`, `PL_PESEL`, `SG_NRIC_FIN`, `AU_ABN` (mod-89), `AU_TFN`,
`AU_ACN`, `AU_MEDICARE`, `IN_AADHAAR` (Verhoeff), `FI_PERSONAL_IDENTITY_CODE`,
`IT_VAT_CODE`, `CA_SIN` (Luhn), `BR_CPF`, `BR_CNPJ`, `NL_BSN`, `TR_TCKN`,
`BE_NRN` (mod-97), `PT_NIF`, `CN_RIC` (ISO 7064), `RU_SNILS`, `DE_TAX_ID`,
`SE_PERSONNUMMER` (Luhn), `ZA_ID` (Luhn), `KR_RRN`, `TW_NATIONAL_ID` (mod-10),
`CZ_BIRTH_NUMBER` (mod-11). **Distinctive-pattern:** `CA_POSTAL_CODE`,
`ZA_COMPANY_REGISTRATION` (CIPC). **Pattern-only:** `UK_NINO`,
`IN_PAN`, `IN_VOTER`, `IN_PASSPORT`, `IN_VEHICLE_REGISTRATION`, `IT_FISCAL_CODE`,
`IT_DRIVER_LICENSE`, `SG_UEN`, `US_ITIN`, `US_PASSPORT`, `US_DRIVER_LICENSE`,
`US_BANK_NUMBER`, `JP_MYNUMBER`, `MX_RFC`, `MX_CURP`, `ZA_VAT_NUMBER` — ~61 entity
types total.

**NER** entities (`PERSON`, `LOCATION`, `ORGANIZATION`, `NRP`) are wired through
`NerRecognizer` and activate once an NLP engine with NER is set.

**Name gazetteers** (optional, `names-gazetteer` feature) — `FIRST_NAME` and
`LAST_NAME` recognizers backed by census name lists (~196k first names, ~794k
surnames; probabilities/ranks stripped). Exact token lookup via a `HashSet`
(`GazetteerRecognizer`), not regex, so the large sets stay fast. Off by default
(pulls `flate2` + ~2.6 MB embedded gzipped data). Register explicitly:

```rust
use presidio_analyzer::{gazetteer, RecognizerRegistry, AnalyzerEngine};
let mut reg = RecognizerRegistry::with_predefined("en");
for g in gazetteer::all_gazetteers() { reg.add(g); }
let engine = AnalyzerEngine::new().with_registry(reg);
```

Base score is medium/standalone (0.3) — name lists are precision-limited (many
names are also common words), so gate on downstream conflict resolution or raise
the analyzer threshold for high-precision use.

### Operators ported

`replace`, `redact`, `mask`, `hash` (sha256/sha512), `keep`, `encrypt`,
`decrypt`, `custom`, `surrogate` (local, deterministic fake values per entity
type — a self-contained stand-in for Presidio's Azure-backed `surrogate_ahds`).

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

**NER (`PERSON` / `LOCATION` / `ORGANIZATION` / `NRP`)** — provided by the
**optional** [`presidio-ner`](crates/presidio-ner) crate: pure-Rust
[Candle](https://github.com/huggingface/candle) inference over a HuggingFace BERT
token-classifier. It's a separate crate (not in `default-members`), so the core,
CLI and Python wheel stay lean — the heavy ML deps and the ~250 MB model only
land on machines that opt in. Weights are lazily downloaded (and cached), never
bundled.

```toml
# add only if you want NER
presidio-ner = "0.1"
```
```rust
use presidio_analyzer::AnalyzerEngine;
use presidio_ner::TransformerNerEngine;

let ner = TransformerNerEngine::from_pretrained("dslim/bert-base-NER")? // or from_path(dir)
    .with_min_score(0.5)            // drop low-confidence spans
    .map_label("PER", "PERSON");    // customize model-label -> entity mapping
let engine = AnalyzerEngine::new().with_nlp_engine(Box::new(ner));
let results = engine.analyze("John Smith lives in Paris", "en", None, None);
// -> PERSON "John Smith", LOCATION "Paris"
```

Any HuggingFace BERT `*ForTokenClassification` model works via `from_pretrained`
/ `from_path`; `with_label_mapping` / `map_label` / `with_min_score` /
`with_language` tune label mapping, thresholding and the advertised language.

To bring your own backend, implement `nlp::NlpEngine` directly, populate
`NlpArtifacts::entities`, and pass it via `with_nlp_engine`. The existing
`NerRecognizer` maps model labels onto Presidio entity names.

**Add a custom operator** — register an `operators::Custom` (or any `Operator`)
on the engine's factory via `factory_mut()`.

## Port status

### Ported and tested ✅

| Area | Status |
|------|--------|
| Pattern-recognizer framework, registry, analyzer-engine orchestration | ✅ |
| ~61 entity types; 29 checksum-validated national IDs across ~22 countries + generic `VIN`/`IMEI` | ✅ (parity+) |
| Checksums: Luhn, IBAN mod-97, Base58Check, NHS, PESEL, SG NRIC, AU ABN/TFN/ACN/Medicare, Aadhaar (Verhoeff), FI HETU, BR CPF/CNPJ, NL BSN, TR, BE, PT, CN (ISO 7064), RU SNILS, DE tax-id, SE, ZA, KR, ES NIF/NIE, IT VAT, CA SIN, TW national-id (mod-10), CZ birth-number (mod-11) | ✅ |
| `PHONE_NUMBER` — real libphonenumber (`phonenumber`), full default region set + `Leniency.VALID` grouping emulation | ✅ (parity) |
| Anonymizer operators: replace, redact, mask, hash, keep, encrypt, decrypt, custom, **surrogate** (local) | ✅ (parity) |
| Deanonymizer + AES-CBC encrypt/decrypt | ✅ |
| `OperatorResult.score` — detection confidence carried into anonymizer output for audit/compliance (upstream #2057) | ✅ |
| Per-call options: `allow_list` (exact/regex), ad-hoc recognizers, supplemental `context` | ✅ |
| Context-aware score enhancement, conflict resolution | ✅ |
| **NER** (`PERSON`/`LOCATION`/`ORGANIZATION`/`NRP`) — optional pure-Rust Candle crate (`presidio-ner`), configurable model/labels/threshold | ✅ (English model; CI-verified) |
| **Multi-language** — pattern/checksum/phone PII works for any language code; **per-language NER routing** (`with_nlp_engine_for`) | ✅ |
| **HTTP service + Docker** — `presidio-server` (Presidio-style REST API) | ✅ |
| **Python bindings** — `presidio-rs` on PyPI (PyO3/maturin) | ✅ |

### Enabled by the seam, needs data/models (not architecture)

- **Per-language NER weights** (e.g. a French `camembert-ner`) — wire via
  `with_nlp_engine_for("fr", …)`.
- **Per-language context-word packs** and a **real lemmatizer** — supply a
  language-specific `NlpEngine` (the default one only lowercases).
- **DATE_TIME** — regex-based; upstream also uses a date NER.

### Out of scope — will NOT be covered ❌

These are **separate Presidio products** with fundamentally different dependency
footprints (OCR, image/dataframe tooling). They are intentionally **not** part of
this port and there are no plans to add them:

- **`presidio-image-redactor`** — OCR + image bounding-box redaction. ❌ Not covered.
- **`presidio-structured`** — tabular / JSON / DataFrame de-identification. ❌ Not covered.

Everything else from `presidio-analyzer` and `presidio-anonymizer` (plus REST
services and Python bindings) is ported.

## Testing

```bash
cargo test        # unit + integration + doctests
```
