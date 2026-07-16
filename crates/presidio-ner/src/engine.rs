//! Candle BERT token-classification NER engine.
//!
//! Loads a HuggingFace `*ForTokenClassification` BERT (e.g. `dslim/bert-base-NER`)
//! as a Candle [`BertModel`] encoder plus a linear `classifier` head, runs a
//! forward pass, softmaxes per token, and hands BIO predictions to
//! [`crate::decode::decode_bio`].

use std::path::Path;

use anyhow::{Context, Result};
use candle_core::{Device, Tensor, D};
use candle_nn::{linear, Linear, Module, VarBuilder};
use candle_transformers::models::bert::{BertModel, Config, DTYPE};
use hf_hub::api::sync::Api;
use tokenizers::Tokenizer;

use presidio_analyzer::{NerEntity, NlpArtifacts, NlpEngine};

use crate::decode::{decode_bio, TokenPred};

pub struct TransformerNerEngine {
    model: BertModel,
    classifier: Linear,
    tokenizer: Tokenizer,
    id2label: Vec<String>,
    device: Device,
    language: String,
}

impl TransformerNerEngine {
    /// Download (and cache) a model from the Hugging Face Hub, then load it.
    /// Needs `config.json`, `model.safetensors`, and either `tokenizer.json` or
    /// `vocab.txt` (WordPiece) in the repo.
    pub fn from_pretrained(model_id: &str) -> Result<Self> {
        let api = Api::new()?;
        let repo = api.model(model_id.to_string());
        let config = repo.get("config.json").context("fetch config.json")?;
        let weights = repo
            .get("model.safetensors")
            .context("fetch model.safetensors")?;
        let tokenizer = match repo.get("tokenizer.json") {
            Ok(p) => load_tokenizer_json(&p)?,
            Err(_) => {
                build_tokenizer_from_vocab(&repo.get("vocab.txt").context("fetch vocab.txt")?)?
            }
        };
        Self::from_parts(&config, &weights, tokenizer)
    }

    /// Load a model from a local directory.
    pub fn from_path(dir: impl AsRef<Path>) -> Result<Self> {
        let d = dir.as_ref();
        let tj = d.join("tokenizer.json");
        let tokenizer = if tj.exists() {
            load_tokenizer_json(&tj)?
        } else {
            build_tokenizer_from_vocab(&d.join("vocab.txt"))?
        };
        Self::from_parts(
            &d.join("config.json"),
            &d.join("model.safetensors"),
            tokenizer,
        )
    }

    fn from_parts(config: &Path, weights: &Path, tokenizer: Tokenizer) -> Result<Self> {
        let device = Device::Cpu;
        let config_str = std::fs::read_to_string(config).context("read config.json")?;
        let cfg: Config = serde_json::from_str(&config_str).context("parse bert config")?;
        let id2label = parse_id2label(&config_str)?;

        let vb = unsafe {
            VarBuilder::from_mmaped_safetensors(&[weights.to_path_buf()], DTYPE, &device)?
        };
        let model = BertModel::load(vb.clone(), &cfg).context("load bert encoder")?;
        let classifier = linear(cfg.hidden_size, id2label.len(), vb.pp("classifier"))
            .context("load classifier head")?;

        Ok(Self {
            model,
            classifier,
            tokenizer,
            id2label,
            device,
            language: "en".to_string(),
        })
    }

    fn predict(&self, text: &str) -> Result<Vec<NerEntity>> {
        let enc = self
            .tokenizer
            .encode(text, true)
            .map_err(|e| anyhow::anyhow!("encode: {e}"))?;

        let ids = enc.get_ids();
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let type_ids = enc.get_type_ids();
        let attn = enc.get_attention_mask();
        let offsets = enc.get_offsets();
        let special = enc.get_special_tokens_mask();

        let input_ids = Tensor::new(ids, &self.device)?.unsqueeze(0)?;
        let type_ids_t = Tensor::new(type_ids, &self.device)?.unsqueeze(0)?;
        let attn_t = Tensor::new(attn, &self.device)?.unsqueeze(0)?;

        let sequence = self.model.forward(&input_ids, &type_ids_t, Some(&attn_t))?;
        let logits = self.classifier.forward(&sequence)?.squeeze(0)?; // [seq, num_labels]
        let probs = candle_nn::ops::softmax(&logits, D::Minus1)?;
        let probs: Vec<Vec<f32>> = probs.to_vec2()?;

        let mut preds = Vec::with_capacity(ids.len());
        for (i, row) in probs.iter().enumerate() {
            let (arg, &p) = row
                .iter()
                .enumerate()
                .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
                .unwrap_or((0, &0.0));
            let (start, end) = offsets[i];
            preds.push(TokenPred {
                start,
                end,
                label: self
                    .id2label
                    .get(arg)
                    .cloned()
                    .unwrap_or_else(|| "O".to_string()),
                score: p as f64,
                is_special: special.get(i).copied().unwrap_or(0) == 1,
            });
        }
        Ok(decode_bio(&preds))
    }
}

impl NlpEngine for TransformerNerEngine {
    fn process(&self, text: &str, language: &str) -> NlpArtifacts {
        // Inference failures degrade to "no NER" rather than panicking the pipeline.
        let entities = self.predict(text).unwrap_or_default();
        NlpArtifacts {
            tokens: Vec::new(),
            entities,
            language: language.to_string(),
        }
    }

    fn is_available(&self, language: &str) -> bool {
        language == self.language
    }
}

fn load_tokenizer_json(path: &Path) -> Result<Tokenizer> {
    Tokenizer::from_file(path).map_err(|e| anyhow::anyhow!("load tokenizer.json: {e}"))
}

/// Build a BERT WordPiece tokenizer from a `vocab.txt` (for models that ship no
/// fast `tokenizer.json`, e.g. `dslim/bert-base-NER`). Cased normalization.
fn build_tokenizer_from_vocab(vocab: &Path) -> Result<Tokenizer> {
    use tokenizers::models::wordpiece::WordPiece;
    use tokenizers::normalizers::BertNormalizer;
    use tokenizers::pre_tokenizers::bert::BertPreTokenizer;
    use tokenizers::processors::bert::BertProcessing;

    let vocab_str = vocab.to_str().context("vocab path not utf-8")?;
    let wp = WordPiece::from_file(vocab_str)
        .unk_token("[UNK]".to_string())
        .build()
        .map_err(|e| anyhow::anyhow!("build wordpiece: {e}"))?;

    let mut tok = Tokenizer::new(wp);
    // clean_text, handle_chinese_chars, strip_accents=false, lowercase=false (cased).
    tok.with_normalizer(Some(BertNormalizer::new(true, true, Some(false), false)));
    tok.with_pre_tokenizer(Some(BertPreTokenizer));
    let cls = tok.token_to_id("[CLS]").context("vocab missing [CLS]")?;
    let sep = tok.token_to_id("[SEP]").context("vocab missing [SEP]")?;
    tok.with_post_processor(Some(BertProcessing::new(
        ("[SEP]".to_string(), sep),
        ("[CLS]".to_string(), cls),
    )));
    Ok(tok)
}

/// Build the ordered `id -> label` list from a HF config's `id2label` map.
pub(crate) fn parse_id2label(config_str: &str) -> Result<Vec<String>> {
    let v: serde_json::Value = serde_json::from_str(config_str)?;
    let map = v
        .get("id2label")
        .and_then(|m| m.as_object())
        .context("config has no id2label map")?;
    let mut pairs: Vec<(usize, String)> = map
        .iter()
        .map(|(k, val)| {
            (
                k.parse::<usize>().unwrap_or(usize::MAX),
                val.as_str().unwrap_or("O").to_string(),
            )
        })
        .collect();
    pairs.sort_by_key(|(i, _)| *i);
    Ok(pairs.into_iter().map(|(_, l)| l).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_id2label_in_order() {
        let cfg = r#"{"id2label": {"0": "O", "1": "B-PER", "2": "I-PER", "3": "B-LOC"}}"#;
        assert_eq!(
            parse_id2label(cfg).unwrap(),
            vec!["O", "B-PER", "I-PER", "B-LOC"]
        );
    }

    #[test]
    fn missing_id2label_errors() {
        assert!(parse_id2label(r#"{"foo": 1}"#).is_err());
    }
}
