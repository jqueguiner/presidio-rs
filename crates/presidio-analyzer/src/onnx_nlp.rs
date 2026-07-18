//! ONNX part-of-speech NLP engine (feature `onnx-pos`).
//!
//! A quantized UPOS token-classifier (e.g. an xlm-roberta UD-POS model exported
//! to ONNX and int8-quantized) run via `onnxruntime`, wrapped as an
//! [`NlpEngine`](crate::nlp::NlpEngine) so its POS tags flow into recognizers —
//! in particular the gazetteer POS gate
//! ([`GazetteerRecognizer::with_pos_gate`](crate::gazetteer::GazetteerRecognizer::with_pos_gate)).
//!
//! Model directory layout ([`OnnxNlpEngine::from_dir`]):
//!   - `model.quant.onnx` — the (quantized) token-classification model
//!   - `tokenizer.json`    — HF fast tokenizer
//!   - `id2label.json`     — `{ "0": "PROPN", ... }` label map
//!
//! Uses `load-dynamic`: set `ORT_DYLIB_PATH` to a `libonnxruntime.so` at runtime.

use std::error::Error;
use std::path::Path;
use std::sync::Mutex;

use ndarray::Array2;
use ort::session::Session;
use ort::value::Value;
use tokenizers::Tokenizer;

use crate::nlp::{NlpArtifacts, NlpEngine, Token};

/// Word-token matcher (same shape as the gazetteer's), so emitted tokens align
/// with the spans gazetteers match on.
fn word_spans(text: &str) -> Vec<(usize, usize)> {
    let re = regex::Regex::new(r"[\p{L}\p{N}][\p{L}\p{N}'\-]*").unwrap();
    re.find_iter(text).map(|m| (m.start(), m.end())).collect()
}

/// POS engine backed by a quantized ONNX UPOS token-classifier.
pub struct OnnxNlpEngine {
    session: Mutex<Session>,
    tokenizer: Tokenizer,
    id2label: Vec<String>,
    /// Approximate max characters per inference window (keeps sub-token count
    /// under the model's limit; long docs are chunked on whitespace).
    chunk_chars: usize,
}

impl OnnxNlpEngine {
    /// Load from a directory containing `model.quant.onnx`, `tokenizer.json`,
    /// `id2label.json`.
    pub fn from_dir(dir: impl AsRef<Path>) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let dir = dir.as_ref();
        let session =
            Mutex::new(Session::builder()?.commit_from_file(dir.join("model.quant.onnx"))?);
        let tokenizer = Tokenizer::from_file(dir.join("tokenizer.json"))?;
        let raw: std::collections::HashMap<String, String> =
            serde_json::from_reader(std::fs::File::open(dir.join("id2label.json"))?)?;
        let n = raw.len();
        let mut id2label = vec![String::new(); n];
        for (k, v) in raw {
            let i: usize = k.parse()?;
            if i < n {
                id2label[i] = v;
            }
        }
        Ok(Self {
            session,
            tokenizer,
            id2label,
            chunk_chars: 1200,
        })
    }

    /// POS-tag one chunk; returns `(char_start, upos)` for the first sub-token of
    /// each word piece, offsets relative to the chunk.
    fn tag_chunk(&self, text: &str) -> Vec<(usize, String)> {
        let enc = match self.tokenizer.encode(text, true) {
            Ok(e) => e,
            Err(_) => return Vec::new(),
        };
        let ids: Vec<i64> = enc.get_ids().iter().map(|&x| x as i64).collect();
        let mask: Vec<i64> = enc.get_attention_mask().iter().map(|&x| x as i64).collect();
        let offsets = enc.get_offsets();
        let seq = ids.len();
        if seq == 0 {
            return Vec::new();
        }
        let id_arr = match Array2::from_shape_vec((1, seq), ids) {
            Ok(a) => a,
            Err(_) => return Vec::new(),
        };
        let mask_arr = match Array2::from_shape_vec((1, seq), mask) {
            Ok(a) => a,
            Err(_) => return Vec::new(),
        };
        let (id_v, mask_v) = match (Value::from_array(id_arr), Value::from_array(mask_arr)) {
            (Ok(a), Ok(b)) => (a, b),
            _ => return Vec::new(),
        };
        let mut sess = match self.session.lock() {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let outputs = match sess.run(ort::inputs![
            "input_ids" => id_v,
            "attention_mask" => mask_v,
        ]) {
            Ok(o) => o,
            Err(_) => return Vec::new(),
        };
        let extracted = match outputs["logits"].try_extract_tensor::<f32>() {
            Ok(t) => t,
            Err(_) => return Vec::new(),
        };
        let (shape, data) = extracted;
        let num_labels = *shape.last().unwrap_or(&0) as usize;
        if num_labels == 0 {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut last_word_start: Option<usize> = None;
        for (t, &(a, b)) in offsets.iter().enumerate().take(seq) {
            if a == b {
                continue; // special token
            }
            if last_word_start == Some(a) {
                continue; // continuation sub-token of the same word
            }
            last_word_start = Some(a);
            let row = &data[t * num_labels..(t + 1) * num_labels];
            let arg = row
                .iter()
                .enumerate()
                .max_by(|x, y| x.1.partial_cmp(y.1).unwrap())
                .map(|(i, _)| i)
                .unwrap_or(0);
            if let Some(lbl) = self.id2label.get(arg) {
                out.push((a, lbl.clone()));
            }
        }
        out
    }
}

impl NlpEngine for OnnxNlpEngine {
    fn process(&self, text: &str, language: &str) -> NlpArtifacts {
        // char-start -> UPOS, tagged over whitespace-bounded chunks
        let mut pos_at: std::collections::HashMap<usize, String> = std::collections::HashMap::new();
        let mut base = 0usize;
        while base < text.len() {
            let mut end = (base + self.chunk_chars).min(text.len());
            while end < text.len() && !text.is_char_boundary(end) {
                end += 1;
            }
            if end < text.len() {
                if let Some(ws) = text[base..end].rfind(char::is_whitespace) {
                    if ws > 0 {
                        end = base + ws;
                    }
                }
            }
            for (a, pos) in self.tag_chunk(&text[base..end]) {
                pos_at.insert(base + a, pos);
            }
            base = end.max(base + 1);
        }
        let tokens = word_spans(text)
            .into_iter()
            .map(|(s, e)| {
                let raw = &text[s..e];
                Token {
                    text: raw.to_string(),
                    lemma: raw.to_lowercase(),
                    start: s,
                    end: e,
                    is_stop: false,
                    pos: pos_at.get(&s).cloned().unwrap_or_default(),
                }
            })
            .collect();
        NlpArtifacts {
            tokens,
            entities: Vec::new(),
            language: language.to_string(),
        }
    }
}
