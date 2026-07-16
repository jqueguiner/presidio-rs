//! BIO tag decoding — pure logic, no ML deps, fully unit-testable.
//!
//! Turns per-token BIO predictions (with byte offsets into the source text) into
//! merged [`NerEntity`] spans, averaging the per-token scores.

use presidio_analyzer::NerEntity;

/// One token's prediction.
#[derive(Debug, Clone)]
pub struct TokenPred {
    /// Byte offset of the token start in the original text.
    pub start: usize,
    /// Byte offset of the token end in the original text.
    pub end: usize,
    /// Predicted label, e.g. `"B-PER"`, `"I-LOC"`, `"O"`.
    pub label: String,
    /// Softmax probability of the predicted label.
    pub score: f64,
    /// Special token ([CLS]/[SEP]/pad) — ignored.
    pub is_special: bool,
}

fn split_bio(label: &str) -> (&str, &str) {
    match label.split_once('-') {
        Some((tag, typ)) => (tag, typ),
        None => ("B", label),
    }
}

struct Span {
    typ: String,
    start: usize,
    end: usize,
    score_sum: f64,
    count: usize,
}

fn flush(cur: &mut Option<Span>, out: &mut Vec<NerEntity>) {
    if let Some(s) = cur.take() {
        out.push(NerEntity {
            entity_type: s.typ,
            start: s.start,
            end: s.end,
            score: s.score_sum / s.count as f64,
        });
    }
}

/// Merge consecutive BIO tokens of the same type into entity spans.
pub fn decode_bio(preds: &[TokenPred]) -> Vec<NerEntity> {
    let mut out = Vec::new();
    let mut cur: Option<Span> = None;

    for p in preds {
        if p.is_special || p.label == "O" {
            flush(&mut cur, &mut out);
            continue;
        }
        let (tag, typ) = split_bio(&p.label);
        match cur {
            Some(ref mut s) if tag == "I" && s.typ == typ => {
                s.end = p.end;
                s.score_sum += p.score;
                s.count += 1;
            }
            _ => {
                flush(&mut cur, &mut out);
                cur = Some(Span {
                    typ: typ.to_string(),
                    start: p.start,
                    end: p.end,
                    score_sum: p.score,
                    count: 1,
                });
            }
        }
    }
    flush(&mut cur, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(start: usize, end: usize, label: &str) -> TokenPred {
        TokenPred {
            start,
            end,
            label: label.to_string(),
            score: 0.9,
            is_special: false,
        }
    }

    fn special() -> TokenPred {
        TokenPred {
            start: 0,
            end: 0,
            label: "O".into(),
            score: 1.0,
            is_special: true,
        }
    }

    #[test]
    fn merges_multi_token_person() {
        // "[CLS] John Smith [SEP]" -> one PERSON span 0..10
        let preds = vec![special(), t(0, 4, "B-PER"), t(5, 10, "I-PER"), special()];
        let ents = decode_bio(&preds);
        assert_eq!(ents.len(), 1);
        assert_eq!(ents[0].entity_type, "PER");
        assert_eq!((ents[0].start, ents[0].end), (0, 10));
    }

    #[test]
    fn separates_adjacent_different_types() {
        let preds = vec![t(0, 4, "B-PER"), t(5, 10, "B-LOC")];
        let ents = decode_bio(&preds);
        assert_eq!(ents.len(), 2);
        assert_eq!(ents[0].entity_type, "PER");
        assert_eq!(ents[1].entity_type, "LOC");
    }

    #[test]
    fn outside_tokens_break_spans() {
        let preds = vec![t(0, 4, "B-ORG"), t(5, 7, "O"), t(8, 12, "B-ORG")];
        assert_eq!(decode_bio(&preds).len(), 2);
    }

    #[test]
    fn i_tag_without_matching_b_starts_new_span() {
        // A stray I-PER with no preceding B still yields a span.
        let ents = decode_bio(&[t(0, 4, "I-PER")]);
        assert_eq!(ents.len(), 1);
        assert_eq!(ents[0].entity_type, "PER");
    }

    #[test]
    fn label_without_dash_treated_as_type() {
        let ents = decode_bio(&[t(0, 3, "PER")]);
        assert_eq!(ents.len(), 1);
        assert_eq!(ents[0].entity_type, "PER");
    }
}
