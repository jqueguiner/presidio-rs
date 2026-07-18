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

/// IMEI: strip separators, require 15 digits, then Luhn (mod-10). Valid promotes
/// to 1.0; anything else is discarded.
pub fn validate_imei(text: &str) -> Option<bool> {
    let d: String = text.chars().filter(|c| c.is_ascii_digit()).collect();
    if d.len() != 15 {
        return Some(false);
    }
    Some(luhn_valid(&d))
}

/// VIN transliteration: digits keep their value; letters map A-Z (I, O, Q
/// excluded) to 1-9 per ISO 3779 / NHTSA. Returns `None` for illegal characters.
fn vin_translit(c: char) -> Option<u32> {
    if let Some(d) = c.to_digit(10) {
        return Some(d);
    }
    Some(match c {
        'A' | 'J' => 1,
        'B' | 'K' | 'S' => 2,
        'C' | 'L' | 'T' => 3,
        'D' | 'M' | 'U' => 4,
        'E' | 'N' | 'V' => 5,
        'F' | 'W' => 6,
        'G' | 'P' | 'X' => 7,
        'H' | 'Y' => 8,
        'R' | 'Z' => 9,
        _ => return None,
    })
}

/// VIN: 17 chars, ISO 3779 mod-11 check digit at position 9 (`X` == 10).
/// North-American VINs (WMI 1-5) with a bad check digit are rejected
/// (`Some(false)`); elsewhere a bad check digit yields `None` (many real
/// non-NA VINs omit a valid check digit), preserving the base score.
pub fn validate_vin(text: &str) -> Option<bool> {
    let s: String = text
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if s.len() != 17 {
        return Some(false);
    }
    const WEIGHTS: [u32; 17] = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2];
    let chars: Vec<char> = s.chars().collect();
    let mut sum = 0u32;
    for (i, &c) in chars.iter().enumerate() {
        let Some(v) = vin_translit(c) else {
            return Some(false);
        };
        sum += v * WEIGHTS[i];
    }
    let remainder = sum % 11;
    let expected = if remainder == 10 {
        'X'
    } else {
        char::from_digit(remainder, 10).unwrap()
    };
    let north_american = matches!(chars[0], '1'..='5');
    if chars[8] == expected {
        Some(true)
    } else if north_american {
        Some(false)
    } else {
        None
    }
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
    fn imei() {
        assert_eq!(validate_imei("490154203237518"), Some(true));
        assert_eq!(validate_imei("49-015420-323751-8"), Some(true));
        assert_eq!(validate_imei("490154203237519"), Some(false));
        assert_eq!(validate_imei("12345"), Some(false));
    }

    #[test]
    fn vin() {
        // All-ones VIN: mod-11 check digit resolves to '1' — valid.
        assert_eq!(validate_vin("11111111111111111"), Some(true));
        // North-American (WMI '1') with a wrong check digit -> rejected.
        assert_eq!(validate_vin("12111111111111111"), Some(false));
        assert_eq!(validate_vin("1M8GDM9AXKP042788"), Some(true));
        // Illegal char (I) and wrong length.
        assert_eq!(validate_vin("1I111111111111111"), Some(false));
        assert_eq!(validate_vin("ABC"), Some(false));
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
