//! Checksum / structural validators used to promote or reject pattern matches.
//!
//! Each validator returns:
//!  * `Some(true)`  — validated, score is promoted to [`MAX_SCORE`](crate::MAX_SCORE)
//!  * `Some(false)` — invalid, the match is discarded
//!  * `None`        — no opinion, the pattern's base score is kept
//!
//! This mirrors Presidio's `PatternRecognizer.validate_result` /
//! `invalidate_result` contract.

use sha2::{Digest, Sha256};

fn sha256(data: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().to_vec()
}

/// Luhn (mod-10) check over the digit characters of `s`.
pub fn luhn_valid(s: &str) -> bool {
    let digits: Vec<u32> = s.chars().filter_map(|c| c.to_digit(10)).collect();
    if digits.len() < 2 {
        return false;
    }
    let parity = digits.len() % 2;
    let mut sum = 0u32;
    for (i, &d) in digits.iter().enumerate() {
        let mut v = d;
        if i % 2 == parity {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
    }
    sum.is_multiple_of(10)
}

/// Credit card: strip separators, require 12–19 digits, then Luhn.
pub fn validate_credit_card(text: &str) -> Option<bool> {
    let sanitized: String = text.chars().filter(|c| c.is_ascii_digit()).collect();
    if sanitized.len() < 12 || sanitized.len() > 19 {
        return Some(false);
    }
    Some(luhn_valid(&sanitized))
}

/// IBAN: ISO 13616 mod-97 check (remainder must be 1).
pub fn validate_iban(text: &str) -> Option<bool> {
    let s: String = text
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if s.len() < 15 || s.len() > 34 {
        return Some(false);
    }
    let (first4, rest) = s.split_at(4);
    let rearranged: String = format!("{rest}{first4}");

    // Compute the big number modulo 97 without bignum arithmetic.
    let mut remainder: u32 = 0;
    for ch in rearranged.chars() {
        if let Some(d) = ch.to_digit(10) {
            remainder = (remainder * 10 + d) % 97;
        } else if ch.is_ascii_uppercase() {
            // A=10 ... Z=35 — two decimal digits.
            let v = ch as u32 - 'A' as u32 + 10;
            remainder = (remainder * 100 + v) % 97;
        } else {
            return Some(false);
        }
    }
    Some(remainder == 1)
}

/// Bitcoin/Litecoin legacy address: Base58Check decode and verify the 4-byte
/// double-SHA256 checksum. Both chains share the same Base58Check construction,
/// so this validates `1`/`3` (BTC P2PKH/P2SH) and `L`/`M` (LTC) addresses.
pub fn validate_btc(text: &str) -> Option<bool> {
    let Some(data) = base58_decode(text) else {
        return Some(false);
    };
    if data.len() < 5 {
        return Some(false);
    }
    let (payload, checksum) = data.split_at(data.len() - 4);
    let hash = sha256(&sha256(payload));
    Some(&hash[0..4] == checksum)
}

/// CRYPTO dispatch validator covering the three address families the recognizer
/// matches. Legacy Base58 addresses (BTC/LTC) are checksum-verified and promoted
/// to 1.0; Ethereum (`0x…`) and bech32 (`bc1…`/`ltc1…`) are validated for shape
/// only and left at the pattern's medium confidence — enforcing EIP-55 / bech32
/// checksums would drop the many un-checksummed addresses seen in synthetic and
/// user-entered data, hurting recall for a high-precision pattern.
pub fn validate_crypto(text: &str) -> Option<bool> {
    // Ethereum: 0x followed by exactly 40 hex nibbles.
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        return if hex.len() == 40 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            None // shape ok (already guaranteed by regex); keep medium confidence
        } else {
            Some(false)
        };
    }
    // Bech32 SegWit (BTC bc1…, LTC ltc1…): shape validated by the regex charset.
    let lower = text.to_ascii_lowercase();
    if lower.starts_with("bc1") || lower.starts_with("ltc1") {
        return None;
    }
    // Legacy Base58Check (BTC + LTC).
    validate_btc(text)
}

/// US SSN: reject structurally-impossible numbers (area 000/666/9xx, group 00,
/// serial 0000). Returns `None` for plausible numbers so the pattern's medium
/// confidence score is preserved rather than promoted to 1.0.
pub fn validate_us_ssn(text: &str) -> Option<bool> {
    let d: String = text.chars().filter(|c| c.is_ascii_digit()).collect();
    if d.len() != 9 {
        return Some(false);
    }
    let area = &d[0..3];
    let group = &d[3..5];
    let serial = &d[5..9];
    if area == "000" || area == "666" || area.starts_with('9') || group == "00" || serial == "0000"
    {
        return Some(false);
    }
    None
}

const B58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Decode a Base58 (Bitcoin alphabet) string into bytes. Returns `None` on any
/// character outside the alphabet.
fn base58_decode(s: &str) -> Option<Vec<u8>> {
    let mut bytes: Vec<u8> = Vec::with_capacity(s.len());
    for ch in s.bytes() {
        let value = B58.iter().position(|&b| b == ch)? as u32;
        let mut carry = value;
        for byte in bytes.iter_mut() {
            carry += (*byte as u32) * 58;
            *byte = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    // Leading '1's in Base58 encode leading zero bytes.
    for ch in s.bytes() {
        if ch == b'1' {
            bytes.push(0);
        } else {
            break;
        }
    }
    bytes.reverse();
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn luhn() {
        assert!(luhn_valid("4111111111111111"));
        assert!(!luhn_valid("4111111111111112"));
    }

    #[test]
    fn credit_card() {
        assert_eq!(validate_credit_card("4111-1111-1111-1111"), Some(true));
        assert_eq!(validate_credit_card("1234-5678-9012-3456"), Some(false));
    }

    #[test]
    fn iban() {
        assert_eq!(validate_iban("GB82 WEST 1234 5698 7654 32"), Some(true));
        assert_eq!(validate_iban("GB00 WEST 1234 5698 7654 32"), Some(false));
    }

    #[test]
    fn btc() {
        assert_eq!(
            validate_btc("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"),
            Some(true)
        );
        assert_eq!(
            validate_btc("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3"),
            Some(false)
        );
    }

    #[test]
    fn crypto_dispatch() {
        // Legacy Base58 (BTC/LTC): checksum-verified.
        assert_eq!(
            validate_crypto("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"),
            Some(true)
        );
        assert_eq!(
            validate_crypto("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3"),
            Some(false)
        );
        // Ethereum: shape-only -> None (keeps the pattern's medium confidence).
        assert_eq!(
            validate_crypto("0x32Be343B94f860124dC4fEe278FDCBD38C102D88"),
            None
        );
        assert_eq!(validate_crypto("0x1234"), Some(false)); // wrong length
        // Bech32 SegWit (BTC/LTC): shape-only -> None.
        assert_eq!(
            validate_crypto("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"),
            None
        );
        assert_eq!(
            validate_crypto("ltc1qzvcgmntglcuv4smv3lzj6k8szcvsrmvk0phrr9"),
            None
        );
    }
}
