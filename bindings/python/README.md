# presidio-rs (Python)

Python bindings for [presidio-rust](https://github.com/jqueguiner/presidio-rs) —
Rust-powered PII detection & anonymization, a port of Microsoft Presidio.

```bash
pip install presidio-rs
```

```python
import presidio_rs

presidio_rs.analyze("card 4095-2609-9393-4932, ssn 078-05-1120")
# [{'entity_type': 'CREDIT_CARD', 'start': 5, 'end': 24, 'score': 1.0},
#  {'entity_type': 'US_SSN', 'start': 30, 'end': 41, 'score': 0.4}]

presidio_rs.anonymize("card 4095-2609-9393-4932", operator="mask", masking_char="#")
# 'card ###################'

presidio_rs.supported_entities()
# ['CREDIT_CARD', 'CRYPTO', 'DATE_TIME', ...]
```

## API

| Function | Returns |
|----------|---------|
| `analyze(text, language="en", entities=None, score_threshold=None)` | `list[dict]` |
| `anonymize(text, language="en", operator="replace", new_value=None, masking_char="*", entities=None, score_threshold=None)` | `str` |
| `supported_entities(language="en")` | `list[str]` |

Built with [PyO3](https://pyo3.rs) + [maturin](https://www.maturin.rs).
