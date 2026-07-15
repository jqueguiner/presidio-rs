//! The built-in operators.
//!
//! Ports of the files under `presidio_anonymizer/operators/`:
//! replace, redact, mask, hash, keep, encrypt, decrypt, custom.

use std::collections::HashMap;

use serde_json::Value;
use sha2::{Digest, Sha256, Sha512};

use crate::aes_cipher;
use crate::operator::{bool_param, int_param, str_param, Operator, OperatorType};

/// `replace` — swap the entity with `new_value`, defaulting to `<ENTITY_TYPE>`.
pub struct Replace;
impl Operator for Replace {
    fn operator_name(&self) -> &str {
        "replace"
    }
    fn operator_type(&self) -> OperatorType {
        OperatorType::Anonymize
    }
    fn operate(&self, _text: &str, params: &HashMap<String, Value>) -> anyhow::Result<String> {
        if let Some(v) = str_param(params, "new_value") {
            if !v.is_empty() {
                return Ok(v.to_string());
            }
        }
        let entity = str_param(params, "entity_type").unwrap_or("ENTITY");
        Ok(format!("<{entity}>"))
    }
}

/// `redact` — remove the entity entirely (replace with empty string).
pub struct Redact;
impl Operator for Redact {
    fn operator_name(&self) -> &str {
        "redact"
    }
    fn operator_type(&self) -> OperatorType {
        OperatorType::Anonymize
    }
    fn operate(&self, _text: &str, _params: &HashMap<String, Value>) -> anyhow::Result<String> {
        Ok(String::new())
    }
}

/// `keep` — leave the entity untouched (used to detect-but-not-redact).
pub struct Keep;
impl Operator for Keep {
    fn operator_name(&self) -> &str {
        "keep"
    }
    fn operator_type(&self) -> OperatorType {
        OperatorType::Anonymize
    }
    fn operate(&self, text: &str, _params: &HashMap<String, Value>) -> anyhow::Result<String> {
        Ok(text.to_string())
    }
}

/// `mask` — replace `chars_to_mask` characters with `masking_char`, optionally
/// from the end of the string.
pub struct Mask;
impl Operator for Mask {
    fn operator_name(&self) -> &str {
        "mask"
    }
    fn operator_type(&self) -> OperatorType {
        OperatorType::Anonymize
    }
    fn validate(&self, params: &HashMap<String, Value>) -> anyhow::Result<()> {
        if let Some(mc) = str_param(params, "masking_char") {
            if mc.chars().count() != 1 {
                anyhow::bail!("masking_char must be exactly one character");
            }
        }
        if let Some(n) = int_param(params, "chars_to_mask") {
            if n < 0 {
                anyhow::bail!("chars_to_mask must be non-negative");
            }
        }
        Ok(())
    }
    fn operate(&self, text: &str, params: &HashMap<String, Value>) -> anyhow::Result<String> {
        let mask_char = str_param(params, "masking_char")
            .and_then(|s| s.chars().next())
            .unwrap_or('*');
        let chars: Vec<char> = text.chars().collect();
        let len = chars.len();
        let to_mask = int_param(params, "chars_to_mask")
            .map(|n| (n as usize).min(len))
            .unwrap_or(len);
        let from_end = bool_param(params, "from_end").unwrap_or(false);

        let mut out: Vec<char> = chars;
        if from_end {
            for c in out.iter_mut().skip(len - to_mask) {
                *c = mask_char;
            }
        } else {
            for c in out.iter_mut().take(to_mask) {
                *c = mask_char;
            }
        }
        Ok(out.into_iter().collect())
    }
}

/// `hash` — replace with a hex digest. `hash_type` in {sha256 (default), sha512}.
pub struct Hash;
impl Operator for Hash {
    fn operator_name(&self) -> &str {
        "hash"
    }
    fn operator_type(&self) -> OperatorType {
        OperatorType::Anonymize
    }
    fn validate(&self, params: &HashMap<String, Value>) -> anyhow::Result<()> {
        if let Some(t) = str_param(params, "hash_type") {
            if !matches!(t, "sha256" | "sha512") {
                anyhow::bail!("hash_type must be one of: sha256, sha512");
            }
        }
        Ok(())
    }
    fn operate(&self, text: &str, params: &HashMap<String, Value>) -> anyhow::Result<String> {
        let hash_type = str_param(params, "hash_type").unwrap_or("sha256");
        let digest = match hash_type {
            "sha512" => {
                let mut h = Sha512::new();
                h.update(text.as_bytes());
                hex::encode(h.finalize())
            }
            _ => {
                let mut h = Sha256::new();
                h.update(text.as_bytes());
                hex::encode(h.finalize())
            }
        };
        Ok(digest)
    }
}

/// `encrypt` — AES-CBC encrypt with `key`, output Base64(IV ‖ ciphertext).
pub struct Encrypt;
impl Operator for Encrypt {
    fn operator_name(&self) -> &str {
        "encrypt"
    }
    fn operator_type(&self) -> OperatorType {
        OperatorType::Anonymize
    }
    fn validate(&self, params: &HashMap<String, Value>) -> anyhow::Result<()> {
        let key = str_param(params, "key").ok_or_else(|| anyhow::anyhow!("`key` is required"))?;
        if !aes_cipher::is_valid_key_size(key.len()) {
            anyhow::bail!("`key` must be 16, 24 or 32 bytes long");
        }
        Ok(())
    }
    fn operate(&self, text: &str, params: &HashMap<String, Value>) -> anyhow::Result<String> {
        let key = str_param(params, "key").ok_or_else(|| anyhow::anyhow!("`key` is required"))?;
        aes_cipher::encrypt(key.as_bytes(), text)
    }
}

/// `decrypt` — reverse of [`Encrypt`]. Deanonymize operator.
pub struct Decrypt;
impl Operator for Decrypt {
    fn operator_name(&self) -> &str {
        "decrypt"
    }
    fn operator_type(&self) -> OperatorType {
        OperatorType::Deanonymize
    }
    fn validate(&self, params: &HashMap<String, Value>) -> anyhow::Result<()> {
        let key = str_param(params, "key").ok_or_else(|| anyhow::anyhow!("`key` is required"))?;
        if !aes_cipher::is_valid_key_size(key.len()) {
            anyhow::bail!("`key` must be 16, 24 or 32 bytes long");
        }
        Ok(())
    }
    fn operate(&self, text: &str, params: &HashMap<String, Value>) -> anyhow::Result<String> {
        let key = str_param(params, "key").ok_or_else(|| anyhow::anyhow!("`key` is required"))?;
        aes_cipher::decrypt(key.as_bytes(), text)
    }
}

/// `custom` — apply a user-supplied closure. Because the transform is a Rust
/// function (not JSON), register instances directly with the factory rather than
/// selecting by config name alone.
pub struct Custom {
    name: String,
    op_type: OperatorType,
    #[allow(clippy::type_complexity)]
    func: Box<dyn Fn(&str) -> String + Send + Sync>,
}

impl Custom {
    pub fn new(
        name: impl Into<String>,
        op_type: OperatorType,
        func: impl Fn(&str) -> String + Send + Sync + 'static,
    ) -> Self {
        Self {
            name: name.into(),
            op_type,
            func: Box::new(func),
        }
    }
}

impl Operator for Custom {
    fn operator_name(&self) -> &str {
        &self.name
    }
    fn operator_type(&self) -> OperatorType {
        self.op_type
    }
    fn operate(&self, text: &str, _params: &HashMap<String, Value>) -> anyhow::Result<String> {
        Ok((self.func)(text))
    }
}
