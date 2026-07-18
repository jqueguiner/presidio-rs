# Gazetteer data

Canonical datasets for the gazetteer recognizers (see `../src/gazetteer.rs`).
For each dataset, `.parquet` (flat, single `name` column, zstd) is the source of
truth and `.txt.gz` (one entry/line) is a byte-for-byte set-equivalent that the
recognizer decompresses with `flate2` at load — avoiding an Arrow/Parquet runtime
dependency in the crate.

| Dataset | Rows | Feature / Entity | Source |
|---------|------|------------------|--------|
| `first_names` | 195,943 | `names-gazetteer` / `FIRST_NAME` | multi-country census names DB |
| `last_names`  | 794,385 | `names-gazetteer` / `LAST_NAME` | multi-country census names DB |
| `cities`      | 706,512 | `cities-gazetteer` / `LOCATION` | GeoNames `cities500` (name + `alternatenames`) |
| `orgs`        | 3,166,828 | `orgs-gazetteer` / `ORGANIZATION` | GLEIF golden copy (`Entity.LegalName`) |
| `tickers`     | 9,862 | `tickers-gazetteer` / `STOCK_TICKER` | SEC `company_tickers.json` |

## Provenance & normalization

All probability, rank, country, gender, phonetic, coordinate, population, LEI and
other metadata columns were **stripped** — only the surface name/symbol is kept.

- **Names / cities / orgs**: lowercased, reduced to letters/digits/space/hyphen,
  whitespace collapsed, length ≥ 3, deduplicated. Cities include GeoNames
  multilingual `alternatenames`; org `&` is folded to a space (tokens split on it).
- **Tickers**: uppercased, alphabetic, length 2–6, deduplicated (matched
  case-sensitively so they don't fire on common lowercase words).

## Regenerating the `.gz` from the `.parquet`

```python
import pyarrow.parquet as pq, gzip
for n in ("first_names", "last_names", "cities", "orgs", "tickers"):
    names = pq.read_table(f"{n}.parquet").column("name").to_pylist()
    with gzip.open(f"{n}.txt.gz", "wt", encoding="utf-8", compresslevel=9) as f:
        f.write("\n".join(names) + "\n")
```

## Regenerating the `.gz` from the `.parquet`

```python
import pyarrow.parquet as pq, gzip
for n in ("first_names", "last_names"):
    names = pq.read_table(f"{n}.parquet").column("name").to_pylist()
    with gzip.open(f"{n}.txt.gz", "wt", encoding="utf-8", compresslevel=9) as f:
        f.write("\n".join(names) + "\n")
```
