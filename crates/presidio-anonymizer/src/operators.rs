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

/// `surrogate` — replace an entity with a realistic, format-preserving fake value
/// chosen deterministically from the original text (so the same input always maps
/// to the same surrogate, giving consistent de-identification).
///
/// This is a self-contained, local port of the *idea* behind Presidio's
/// `surrogate_ahds` operator. The upstream operator delegates to the Azure Health
/// Data Services de-identification API; that external dependency is intentionally
/// not reproduced here.
pub struct Surrogate;

impl Operator for Surrogate {
    fn operator_name(&self) -> &str {
        "surrogate"
    }
    fn operator_type(&self) -> OperatorType {
        OperatorType::Anonymize
    }
    fn operate(&self, text: &str, params: &HashMap<String, Value>) -> anyhow::Result<String> {
        let entity = str_param(params, "entity_type").unwrap_or("ENTITY");
        let mut rng = DetRng::seed_from_text(text);
        Ok(surrogate_value(entity, &mut rng))
    }
}

/// Deterministic SplitMix64 seeded from a SHA-256 of the source text.
struct DetRng(u64);

impl DetRng {
    fn seed_from_text(text: &str) -> Self {
        let mut h = Sha256::new();
        h.update(text.as_bytes());
        let d = h.finalize();
        let mut b = [0u8; 8];
        b.copy_from_slice(&d[0..8]);
        Self(u64::from_le_bytes(b))
    }
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[(self.next() as usize) % items.len()]
    }
    fn digits(&mut self, n: usize) -> String {
        (0..n)
            .map(|_| char::from(b'0' + (self.next() % 10) as u8))
            .collect()
    }
    fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.next() % (hi - lo)
    }
}

const FIRST: &[&str] = &[
    "James",
    "Mary",
    "Robert",
    "Patricia",
    "John",
    "Jennifer",
    "Michael",
    "Linda",
    "David",
    "Elizabeth",
    "Maria",
    "Wei",
    "Ahmed",
    "Sofia",
    "Yuki",
    "Omar",
];
const LAST: &[&str] = &[
    "Smith",
    "Johnson",
    "Williams",
    "Brown",
    "Garcia",
    "Miller",
    "Davis",
    "Rodriguez",
    "Martinez",
    "Nguyen",
    "Kim",
    "Khan",
    "Rossi",
    "Silva",
    "Cohen",
    "Dubois",
];
const CITIES: &[&str] = &[
    "Springfield",
    "Riverton",
    "Fairview",
    "Lakeside",
    "Milton",
    "Greenville",
    "Bristol",
    "Ashford",
    "Kingsley",
    "Oakdale",
];
const ORGS: &[&str] = &[
    "Acme Corp",
    "Globex",
    "Initech",
    "Umbrella Ltd",
    "Soylent Inc",
    "Hooli",
    "Vandelay",
    "Wonka Industries",
];

fn luhn_valid_card(rng: &mut DetRng) -> String {
    let mut digits: Vec<u32> = (0..15).map(|_| (rng.next() % 10) as u32).collect();
    // Compute the Luhn check digit for a 16-digit number.
    let mut sum = 0u32;
    for (i, &d) in digits.iter().enumerate() {
        // Position from the right in the final 16-digit number for index i is (15 - i);
        // doubling applies to odd positions from the right (0-based even index here).
        let mut v = d;
        if i % 2 == 0 {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
    }
    let check = (10 - (sum % 10)) % 10;
    digits.push(check);
    digits.iter().map(|d| char::from(b'0' + *d as u8)).collect()
}

fn surrogate_value(entity: &str, rng: &mut DetRng) -> String {
    match entity {
        "PERSON" => format!("{} {}", rng.pick(FIRST), rng.pick(LAST)),
        "EMAIL_ADDRESS" => format!(
            "{}.{}@example.com",
            rng.pick(FIRST).to_lowercase(),
            rng.pick(LAST).to_lowercase()
        ),
        "PHONE_NUMBER" => format!("+1 ({}) {}-{}", rng.digits(3), rng.digits(3), rng.digits(4)),
        "CREDIT_CARD" => luhn_valid_card(rng),
        "US_SSN" => format!("{}-{}-{}", rng.digits(3), rng.digits(2), rng.digits(4)),
        "IP_ADDRESS" => format!(
            "{}.{}.{}.{}",
            rng.range(1, 224),
            rng.next() % 256,
            rng.next() % 256,
            rng.range(1, 255)
        ),
        "LOCATION" => rng.pick(CITIES).to_string(),
        "ORGANIZATION" | "NRP" => rng.pick(ORGS).to_string(),
        "DATE_TIME" => format!(
            "{:04}-{:02}-{:02}",
            rng.range(1950, 2020),
            rng.range(1, 13),
            rng.range(1, 29)
        ),
        other => format!("<{other}>"),
    }
}
