//! Gazetteer (name-lookup) recognizer.
//!
//! Detects entities by exact token / phrase lookup against a large in-memory
//! set, rather than regex — the sets (hundreds of thousands to millions of
//! entries) are far too large for a regex alternation.
//!
//! Backs several reference-data recognizers, each behind its own cargo feature.
//! The data is downloaded and cached on first use (see the [`data`] module), so
//! it works from a crates.io build as well as an in-repo checkout:
//!
//! | Feature | Entity | Source | Size |
//! |---------|--------|--------|------|
//! | `names-gazetteer`   | `FIRST_NAME`, `LAST_NAME` | census names DB | ~196k + ~794k |
//! | `cities-gazetteer`  | `LOCATION`      | GeoNames cities500 | ~707k |
//! | `orgs-gazetteer`    | `ORGANIZATION`  | GLEIF golden copy  | ~3.12M |
//! | `tickers-gazetteer` | `STOCK_TICKER`  | SEC company tickers | ~9.9k |
//!
//! The `GazetteerRecognizer` type itself is always available so callers can
//! build their own gazetteers (single- or multi-word, case-(in)sensitive).

use std::collections::HashSet;
use std::sync::OnceLock;

use regex::Regex;

use crate::entities::{AnalysisExplanation, RecognizerResult};
use crate::nlp::NlpArtifacts;
use crate::recognizer::EntityRecognizer;

/// Word-token matcher: a Unicode letter or digit followed by letters, digits,
/// apostrophes or hyphens (so `O'Brien`, `Jean-Luc`, `3M` tokenize as one token).
fn token_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[\p{L}\p{N}][\p{L}\p{N}'\-]*").unwrap())
}

/// A recognizer that emits a result for each entry of `names` found in the text.
///
/// Single-token by default; set [`with_max_words`](Self::with_max_words) for
/// multi-word entries (cities, organizations), matched greedily longest-first.
/// Lookups are case-insensitive unless [`with_case_sensitive`](Self::with_case_sensitive)
/// is set (stock tickers, which must stay uppercase to avoid matching common
/// words). Entries in `names` must already be normalized to the same casing and
/// single-space-separated.
pub struct GazetteerRecognizer {
    name: String,
    entity: String,
    names: HashSet<String>,
    score: f64,
    /// Matched spans shorter than this many chars are ignored (cuts short-word
    /// false positives).
    min_len: usize,
    /// Maximum number of tokens a single entry may span (default 1).
    max_words: usize,
    /// Match case-sensitively (default false → lookups are lowercased).
    case_sensitive: bool,
    /// Require the matched span to look like a proper noun: reject it when its
    /// first character is a *lowercase* letter (default false). Script-safe —
    /// caseless scripts (CJK, Arabic, Hebrew, …) have no lowercase form and are
    /// always kept, so this only drops lowercase common-word collisions
    /// (`will`, `mark`, `rose`) without hurting recall on uncased text.
    require_proper_noun: bool,
    /// Allowed part-of-speech tags (UPOS) for the matched head token. When set
    /// and the NLP layer supplies a POS for that token, a match is kept only if
    /// its POS is in this set — an independent grammatical signal that
    /// disambiguates homographs (`Rose`/`Mark` = PROPN keep; `Section`/`Milk` =
    /// NOUN drop) which casing alone cannot. When no POS is available it falls
    /// back to the [`require_proper_noun`](Self::with_require_proper_noun) gate.
    pos_gate: Option<Vec<String>>,
}

impl GazetteerRecognizer {
    /// Build a gazetteer from a normalized set of names.
    pub fn new(name: &str, entity: &str, names: HashSet<String>, score: f64) -> Self {
        Self {
            name: name.to_string(),
            entity: entity.to_string(),
            names,
            score,
            min_len: 3,
            max_words: 1,
            case_sensitive: false,
            require_proper_noun: false,
            pos_gate: None,
        }
    }

    /// Override the minimum matched-span length (default 3).
    pub fn with_min_len(mut self, min_len: usize) -> Self {
        self.min_len = min_len;
        self
    }

    /// Allow entries spanning up to `max_words` tokens (default 1).
    pub fn with_max_words(mut self, max_words: usize) -> Self {
        self.max_words = max_words.max(1);
        self
    }

    /// Match case-sensitively (default false).
    pub fn with_case_sensitive(mut self, yes: bool) -> Self {
        self.case_sensitive = yes;
        self
    }

    /// Only emit spans that look like proper nouns — i.e. drop a match whose
    /// first character is a lowercase letter (default false).
    ///
    /// Names/cities/orgs are capitalized wherever they appear in real text, but
    /// the reference sets are huge and lowercased, so unfiltered lookups fire on
    /// every common word that collides with a name or place (`will`, `may`,
    /// `mark`, `rose`, `nice`, `mobile`). Requiring an initial non-lowercase
    /// character removes those collisions. It is script-safe: caseless scripts
    /// have no lowercase form, so uncased matches are always kept.
    pub fn with_require_proper_noun(mut self, yes: bool) -> Self {
        self.require_proper_noun = yes;
        self
    }

    /// Keep only matches whose head token has one of `allowed` UPOS tags, when
    /// the NLP layer provides POS (falls back to the proper-noun/casing gate
    /// otherwise). POS is an independent grammatical signal that disambiguates
    /// homographs casing cannot (`Section`/`Milk` are capitalized but `NOUN`,
    /// so they are dropped; `Rose`/`Mark` are `PROPN`, so kept). Typically
    /// `["PROPN"]` for names/places/orgs.
    pub fn with_pos_gate<I, S>(mut self, allowed: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.pos_gate = Some(allowed.into_iter().map(Into::into).collect());
        self
    }

    /// Number of names in the set.
    pub fn len(&self) -> usize {
        self.names.len()
    }

    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    fn key(&self, s: &str) -> String {
        if self.case_sensitive {
            s.to_string()
        } else {
            s.to_lowercase()
        }
    }

    /// Proper-noun gate: when [`require_proper_noun`](Self::with_require_proper_noun)
    /// is set, reject a match whose first character is a lowercase letter. Chars
    /// with no lowercase form (digits, CJK, Arabic, Hebrew, …) are not lowercase
    /// and therefore always pass, keeping the gate script-safe.
    fn proper_noun_ok(&self, first_tok: &str) -> bool {
        if !self.require_proper_noun {
            return true;
        }
        match first_tok.chars().next() {
            Some(c) => !c.is_lowercase(),
            None => true,
        }
    }

    /// Combined admission gate for a match whose head token starts at byte
    /// `start` with surface `first_tok`. Prefers the POS gate when a POS tag is
    /// available for the head token; otherwise falls back to the proper-noun
    /// (casing) gate. This lets a POS-capable NLP backend drive precision while
    /// keeping the dependency-free default working.
    fn gate_ok(&self, start: usize, first_tok: &str, nlp: Option<&NlpArtifacts>) -> bool {
        if let Some(allowed) = &self.pos_gate {
            if let Some(art) = nlp {
                if let Some(tok) = art
                    .tokens
                    .iter()
                    .find(|t| t.start <= start && start < t.end)
                {
                    if !tok.pos.is_empty() {
                        return allowed.iter().any(|p| p == &tok.pos);
                    }
                }
            }
        }
        self.proper_noun_ok(first_tok)
    }
}

impl EntityRecognizer for GazetteerRecognizer {
    fn name(&self) -> &str {
        &self.name
    }

    fn supported_entities(&self) -> Vec<String> {
        vec![self.entity.clone()]
    }

    fn is_language_agnostic(&self) -> bool {
        // A name / city / org surface-string lookup does not depend on the
        // document language, so gazetteers are active for every language.
        true
    }

    fn analyze(
        &self,
        text: &str,
        entities: &[String],
        nlp: Option<&NlpArtifacts>,
    ) -> Vec<RecognizerResult> {
        if !entities.iter().any(|e| e == &self.entity) {
            return Vec::new();
        }
        let toks: Vec<(usize, usize, &str)> = token_regex()
            .find_iter(text)
            .map(|m| (m.start(), m.end(), m.as_str()))
            .collect();

        let mut out = Vec::new();
        let mut i = 0;
        while i < toks.len() {
            let max_w = self.max_words.min(toks.len() - i);
            let mut w = max_w;
            let mut hit = false;
            while w >= 1 {
                // Join the w tokens with single spaces (matches how entries are normalized).
                let phrase = toks[i..i + w]
                    .iter()
                    .map(|t| t.2)
                    .collect::<Vec<_>>()
                    .join(" ");
                if phrase.chars().count() >= self.min_len
                    && self.gate_ok(toks[i].0, toks[i].2, nlp)
                    && self.names.contains(&self.key(&phrase))
                {
                    let start = toks[i].0;
                    let end = toks[i + w - 1].1;
                    let mut r = RecognizerResult::new(self.entity.clone(), start, end, self.score);
                    r.analysis_explanation = Some(AnalysisExplanation {
                        recognizer: self.name.clone(),
                        original_score: self.score,
                        score: self.score,
                        textual_explanation: Some(format!("'{phrase}' found in gazetteer")),
                        ..Default::default()
                    });
                    out.push(r);
                    i += w;
                    hit = true;
                    break;
                }
                w -= 1;
            }
            if !hit {
                i += 1;
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Dataset gazetteers (feature-gated per dataset)
// ---------------------------------------------------------------------------
//
// The gzipped data is too large to embed in (and ship inside) the crates.io
// package, so it is resolved at first use in this order:
//   1. `$PRESIDIO_GAZETTEER_DIR/<file>`      (explicit override / offline)
//   2. `./data/<file>` or
//      `./crates/presidio-analyzer/data/<file>` (in-repo / git checkout)
//   3. a per-user cache dir, downloading from the pinned GitHub tag if absent
// The download URL is pinned to the crate version's git tag so a given release
// always resolves the data it was built against.

#[cfg(any(
    feature = "names-gazetteer",
    feature = "cities-gazetteer",
    feature = "orgs-gazetteer",
    feature = "tickers-gazetteer",
))]
mod data {
    use super::HashSet;
    use std::io::Read;
    use std::path::PathBuf;

    fn parse_gz(bytes: &[u8]) -> HashSet<String> {
        let mut s = String::new();
        flate2::read::GzDecoder::new(bytes)
            .read_to_string(&mut s)
            .expect("gazetteer data is valid gzip");
        s.lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty())
            .map(|l| l.to_string())
            .collect()
    }

    fn local_path(file: &str) -> Option<PathBuf> {
        if let Ok(dir) = std::env::var("PRESIDIO_GAZETTEER_DIR") {
            let p = PathBuf::from(dir).join(file);
            if p.is_file() {
                return Some(p);
            }
        }
        for base in ["data", "crates/presidio-analyzer/data"] {
            let p = PathBuf::from(base).join(file);
            if p.is_file() {
                return Some(p);
            }
        }
        None
    }

    fn cache_path(file: &str) -> PathBuf {
        let base = dirs::cache_dir()
            .unwrap_or_else(std::env::temp_dir)
            .join("presidio-rs")
            .join(env!("CARGO_PKG_VERSION"));
        let _ = std::fs::create_dir_all(&base);
        base.join(file)
    }

    fn download_to(url: &str, dest: &PathBuf) {
        let mut buf = Vec::new();
        ureq::get(url)
            .call()
            .unwrap_or_else(|e| panic!("failed to fetch gazetteer data from {url}: {e}"))
            .into_reader()
            .read_to_end(&mut buf)
            .expect("read gazetteer download");
        let tmp = dest.with_extension("part");
        std::fs::write(&tmp, &buf).expect("write gazetteer cache");
        std::fs::rename(&tmp, dest).expect("finalize gazetteer cache");
    }

    /// Resolve `file` (e.g. `first_names.txt.gz`) to a decompressed name set,
    /// downloading and caching it on first use if not found locally.
    pub(super) fn load(file: &str) -> HashSet<String> {
        if let Some(p) = local_path(file) {
            return parse_gz(&std::fs::read(&p).expect("read local gazetteer"));
        }
        let cache = cache_path(file);
        if !cache.is_file() {
            let url = format!(
                "https://raw.githubusercontent.com/jqueguiner/presidio-rs/v{}/crates/presidio-analyzer/data/{file}",
                env!("CARGO_PKG_VERSION")
            );
            download_to(&url, &cache);
        }
        parse_gz(&std::fs::read(&cache).expect("read cached gazetteer"))
    }
}

/// `FIRST_NAME` gazetteer — ~196k multi-country first names from the census DB
/// (probabilities/ranks stripped). Base score 0.3 (medium, standalone).
///
/// Data is downloaded and cached on first use (see the [`data`] module).
#[cfg(feature = "names-gazetteer")]
pub fn first_names() -> GazetteerRecognizer {
    GazetteerRecognizer::new(
        "FirstNameGazetteer",
        "FIRST_NAME",
        data::load("first_names.txt.gz"),
        0.3,
    )
    .with_require_proper_noun(true)
    .with_pos_gate(["PROPN"])
}

/// `LAST_NAME` gazetteer — ~794k multi-country surnames from the census DB
/// (probabilities/ranks stripped). Base score 0.3 (medium, standalone).
#[cfg(feature = "names-gazetteer")]
pub fn last_names() -> GazetteerRecognizer {
    GazetteerRecognizer::new(
        "LastNameGazetteer",
        "LAST_NAME",
        data::load("last_names.txt.gz"),
        0.3,
    )
    .with_require_proper_noun(true)
    .with_pos_gate(["PROPN"])
}

/// `LOCATION` gazetteer — ~707k city names + multilingual aliases from GeoNames
/// `cities500` (population/coords stripped). Multi-word (up to 6 tokens).
#[cfg(feature = "cities-gazetteer")]
pub fn cities() -> GazetteerRecognizer {
    GazetteerRecognizer::new(
        "CityGazetteer",
        "LOCATION",
        data::load("cities.txt.gz"),
        0.3,
    )
    .with_max_words(6)
    .with_require_proper_noun(true)
    .with_pos_gate(["PROPN"])
}

/// `ORGANIZATION` gazetteer — ~3.12M organization names from the GLEIF golden
/// copy. Legal-form suffixes (`Inc`, `Corp`, `Ltd`, `GmbH`, …) and a leading
/// `The` are stripped so the core name matches free text (`Apple Inc` → `apple`).
/// Multi-word (up to 10 tokens). Heavy (~23 MB download).
#[cfg(feature = "orgs-gazetteer")]
pub fn organizations() -> GazetteerRecognizer {
    GazetteerRecognizer::new(
        "OrgGazetteer",
        "ORGANIZATION",
        data::load("orgs.txt.gz"),
        0.3,
    )
    .with_max_words(10)
    .with_require_proper_noun(true)
    .with_pos_gate(["PROPN"])
}

/// `STOCK_TICKER` gazetteer — ~9.9k US-listed symbols from the SEC company
/// tickers file. Case-sensitive (uppercase) with a length-2 floor, so it does
/// not match common lowercase words. Base score 0.4.
#[cfg(feature = "tickers-gazetteer")]
pub fn stock_tickers() -> GazetteerRecognizer {
    GazetteerRecognizer::new(
        "StockTickerGazetteer",
        "STOCK_TICKER",
        data::load("tickers.txt.gz"),
        0.4,
    )
    .with_case_sensitive(true)
    .with_min_len(2)
}

/// Every gazetteer whose cargo feature is enabled, ready to register.
pub fn all_gazetteers() -> Vec<Box<dyn EntityRecognizer>> {
    #[allow(unused_mut)]
    let mut v: Vec<Box<dyn EntityRecognizer>> = Vec::new();
    #[cfg(feature = "names-gazetteer")]
    {
        v.push(Box::new(first_names()));
        v.push(Box::new(last_names()));
    }
    #[cfg(feature = "cities-gazetteer")]
    v.push(Box::new(cities()));
    #[cfg(feature = "orgs-gazetteer")]
    v.push(Box::new(organizations()));
    #[cfg(feature = "tickers-gazetteer")]
    v.push(Box::new(stock_tickers()));
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_matches_tokens() {
        let set: HashSet<String> = ["alice", "bob", "carol"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let rec = GazetteerRecognizer::new("G", "FIRST_NAME", set, 0.3);
        let res = rec.analyze("Alice met bob and Dan", &["FIRST_NAME".to_string()], None);
        // "Alice" (case-insensitive) and "bob"; "Dan" not in set.
        assert_eq!(res.len(), 2);
        assert!(res.iter().all(|r| r.entity_type == "FIRST_NAME"));
        assert_eq!(&"Alice met bob and Dan"[res[0].start..res[0].end], "Alice");
        // Not-requested entity -> empty.
        assert!(rec
            .analyze("Alice", &["LAST_NAME".to_string()], None)
            .is_empty());
    }

    #[test]
    fn min_len_filters_short_tokens() {
        let set: HashSet<String> = ["al"].iter().map(|s| s.to_string()).collect();
        let rec = GazetteerRecognizer::new("G", "FIRST_NAME", set, 0.3);
        // Default min_len 3 drops the 2-char token.
        assert!(rec
            .analyze("al", &["FIRST_NAME".to_string()], None)
            .is_empty());
        let rec2 = rec.with_min_len(2);
        assert_eq!(
            rec2.analyze("al", &["FIRST_NAME".to_string()], None).len(),
            1
        );
    }

    #[test]
    fn multi_word_greedy_longest_match() {
        let set: HashSet<String> = ["new york", "york", "san francisco"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let rec = GazetteerRecognizer::new("G", "LOCATION", set, 0.3).with_max_words(2);
        let text = "flew from New York to San Francisco";
        let res = rec.analyze(text, &["LOCATION".to_string()], None);
        // "New York" matched as one 2-token span (not "york" alone), plus "San Francisco".
        assert_eq!(res.len(), 2);
        assert_eq!(&text[res[0].start..res[0].end], "New York");
        assert_eq!(&text[res[1].start..res[1].end], "San Francisco");
    }

    #[test]
    fn case_sensitive_ticker_style() {
        let set: HashSet<String> = ["AA", "AAPL"].iter().map(|s| s.to_string()).collect();
        let rec = GazetteerRecognizer::new("T", "STOCK_TICKER", set, 0.4)
            .with_case_sensitive(true)
            .with_min_len(2);
        // Uppercase symbol matches; lowercase common word does not.
        let res = rec.analyze("bought AAPL today", &["STOCK_TICKER".to_string()], None);
        assert_eq!(res.len(), 1);
        assert!(rec
            .analyze("aapl is a word", &["STOCK_TICKER".to_string()], None)
            .is_empty());
    }

    #[test]
    fn digit_tokens_match() {
        // Digits are part of tokens ("7eleven"), and "3m" works once min_len allows it.
        let set: HashSet<String> = ["7eleven", "3m"].iter().map(|s| s.to_string()).collect();
        let rec = GazetteerRecognizer::new("G", "ORGANIZATION", set, 0.3);
        assert_eq!(
            rec.analyze("shop at 7Eleven", &["ORGANIZATION".to_string()], None)
                .len(),
            1
        );
        // "3M" (2 chars) needs min_len lowered to 2.
        let rec2 = rec.with_min_len(2);
        assert_eq!(
            rec2.analyze("works at 3M", &["ORGANIZATION".to_string()], None)
                .len(),
            1
        );
    }

    #[test]
    fn proper_noun_gate_drops_lowercase_collisions() {
        // "will", "mark", "rose" are real first names but also common English words.
        let set: HashSet<String> = ["will", "mark", "rose"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let rec =
            GazetteerRecognizer::new("G", "FIRST_NAME", set, 0.3).with_require_proper_noun(true);
        let ents = ["FIRST_NAME".to_string()];
        // Capitalized -> kept.
        assert_eq!(rec.analyze("Ask Mark about it", &ents, None).len(), 1);
        // Lowercase common-word use -> dropped.
        assert!(rec.analyze("i will mark the rose", &ents, None).is_empty());
        // Without the gate, all three lowercase words match.
        let open = GazetteerRecognizer::new(
            "G",
            "FIRST_NAME",
            ["will", "mark", "rose"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            0.3,
        );
        assert_eq!(open.analyze("i will mark the rose", &ents, None).len(), 3);
    }

    #[test]
    fn proper_noun_gate_is_script_safe() {
        // Caseless scripts have no lowercase form -> always kept, even with the gate.
        let set: HashSet<String> = ["北京", "東京"].iter().map(|s| s.to_string()).collect();
        let rec = GazetteerRecognizer::new("G", "LOCATION", set, 0.3)
            .with_min_len(1)
            .with_require_proper_noun(true);
        let res = rec.analyze("从 北京 到 東京", &["LOCATION".to_string()], None);
        assert_eq!(res.len(), 2);
    }

    // Build NlpArtifacts with POS tags for a whitespace-tokenized ASCII string.
    fn nlp_with_pos(text: &str, pos: &[(&str, &str)]) -> crate::nlp::NlpArtifacts {
        use crate::nlp::Token;
        let map: std::collections::HashMap<&str, &str> = pos.iter().copied().collect();
        let mut tokens = Vec::new();
        let mut i = 0;
        for w in text.split(' ') {
            if !w.is_empty() {
                tokens.push(Token {
                    text: w.to_string(),
                    lemma: w.to_lowercase(),
                    start: i,
                    end: i + w.len(),
                    is_stop: false,
                    pos: map.get(w).copied().unwrap_or("").to_string(),
                });
            }
            i += w.len() + 1;
        }
        crate::nlp::NlpArtifacts {
            tokens,
            ..Default::default()
        }
    }

    #[test]
    fn pos_gate_drops_wrong_pos_keeps_propn() {
        // "rose" both a name and a verb; "mark" both a name and a verb.
        let set: HashSet<String> = ["rose", "mark"].iter().map(|s| s.to_string()).collect();
        let rec = GazetteerRecognizer::new("G", "FIRST_NAME", set, 0.3).with_pos_gate(["PROPN"]);
        let ents = ["FIRST_NAME".to_string()];
        let text = "Rose Mark";
        // Rose tagged PROPN (kept), Mark tagged VERB (dropped) — casing is identical.
        let nlp = nlp_with_pos(text, &[("Rose", "PROPN"), ("Mark", "VERB")]);
        let res = rec.analyze(text, &ents, Some(&nlp));
        assert_eq!(res.len(), 1);
        assert_eq!(&text[res[0].start..res[0].end], "Rose");
    }

    #[test]
    fn pos_gate_falls_back_to_casing_without_pos() {
        // No NLP / empty POS -> fall back to the proper-noun casing gate.
        let set: HashSet<String> = ["rose"].iter().map(|s| s.to_string()).collect();
        let rec = GazetteerRecognizer::new("G", "FIRST_NAME", set, 0.3)
            .with_require_proper_noun(true)
            .with_pos_gate(["PROPN"]);
        let ents = ["FIRST_NAME".to_string()];
        // No nlp at all -> casing gate: "Rose" kept, "rose" dropped.
        assert_eq!(rec.analyze("Rose", &ents, None).len(), 1);
        assert!(rec.analyze("rose", &ents, None).is_empty());
    }

    #[cfg(feature = "names-gazetteer")]
    #[test]
    fn census_gazetteers_load_and_detect() {
        let fnr = first_names();
        assert!(fnr.len() > 150_000);
        let res = fnr.analyze("my name is Maria", &["FIRST_NAME".to_string()], None);
        assert!(res.iter().any(|r| r.entity_type == "FIRST_NAME"));

        let lnr = last_names();
        assert!(lnr.len() > 100_000);
        let res = lnr.analyze("mr Smith", &["LAST_NAME".to_string()], None);
        assert!(res.iter().any(|r| r.entity_type == "LAST_NAME"));
    }

    #[cfg(feature = "cities-gazetteer")]
    #[test]
    fn city_gazetteer_detects() {
        let c = cities();
        assert!(c.len() > 400_000);
        let text = "travelled to New York and Paris";
        let res = c.analyze(text, &["LOCATION".to_string()], None);
        assert!(res.iter().any(|r| &text[r.start..r.end] == "New York"));
        assert!(res.iter().any(|r| &text[r.start..r.end] == "Paris"));
    }

    #[cfg(feature = "orgs-gazetteer")]
    #[test]
    fn org_gazetteer_detects() {
        let o = organizations();
        assert!(o.len() > 1_000_000);
        // Legal-form suffix stripped -> the bare core name matches free text.
        let text = "shares of Apple rose";
        let res = o.analyze(text, &["ORGANIZATION".to_string()], None);
        assert!(res.iter().any(|r| &text[r.start..r.end] == "Apple"));
        // Multi-word core still matches.
        let text2 = "a Goldman Sachs report";
        let res2 = o.analyze(text2, &["ORGANIZATION".to_string()], None);
        assert!(res2
            .iter()
            .any(|r| &text2[r.start..r.end] == "Goldman Sachs"));
    }

    #[cfg(feature = "tickers-gazetteer")]
    #[test]
    fn ticker_gazetteer_detects() {
        let t = stock_tickers();
        assert!(t.len() > 5_000);
        let res = t.analyze("AAPL and MSFT", &["STOCK_TICKER".to_string()], None);
        assert!(
            res.iter()
                .filter(|r| r.entity_type == "STOCK_TICKER")
                .count()
                >= 2
        );
    }
}
