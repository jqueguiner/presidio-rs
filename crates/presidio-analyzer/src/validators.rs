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

/// Bitcoin address: Base58Check decode and verify the 4-byte double-SHA256 checksum.
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
}
