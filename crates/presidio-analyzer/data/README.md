# Name gazetteer data

Canonical datasets for the `FIRST_NAME` / `LAST_NAME` gazetteer recognizers
(`names-gazetteer` feature, see `../src/gazetteer.rs`).

| File | Rows | Column | Role |
|------|------|--------|------|
| `first_names.parquet` | 195,943 | `name` (string) | canonical source (flat, zstd) |
| `last_names.parquet`  | 794,385 | `name` (string) | canonical source (flat, zstd) |
| `first_names.txt.gz`  | 195,943 | one name/line | derived — loaded by the recognizer |
| `last_names.txt.gz`   | 794,385 | one name/line | derived — loaded by the recognizer |

The `.parquet` files are the source of truth; the `.txt.gz` files are a
byte-for-byte name-set equivalent (verified identical) kept only because the
recognizer decompresses them with `flate2` at load, avoiding an Arrow/Parquet
runtime dependency in the crate.

## Provenance

Both derive from multi-country census names databases. All probability, rank,
country, gender, phonetic and other metadata columns were **stripped** — only
the ASCII name is kept. Names were filtered to alphabetic tokens (length ≥ 3),
lowercased and deduplicated.

## Regenerating the `.gz` from the `.parquet`

```python
import pyarrow.parquet as pq, gzip
for n in ("first_names", "last_names"):
    names = pq.read_table(f"{n}.parquet").column("name").to_pylist()
    with gzip.open(f"{n}.txt.gz", "wt", encoding="utf-8", compresslevel=9) as f:
        f.write("\n".join(names) + "\n")
```
