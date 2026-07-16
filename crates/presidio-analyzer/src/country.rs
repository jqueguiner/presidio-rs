//! Country-specific recognizers.
//!
//! Rust ports of a representative slice of
//! `predefined_recognizers/country_specific/*`, keeping Presidio's entity names.
//! Numbers with a defined check digit are validated (and promoted to 1.0);
//! others rely on a distinctive pattern.

use crate::pattern::Pattern;
use crate::recognizer::{EntityRecognizer, PatternRecognizer};

fn digits(s: &str) -> Vec<u8> {
    s.bytes()
        .filter(|b| b.is_ascii_digit())
        .map(|b| b - b'0')
        .collect()
}

// ---------------------------------------------------------------------------
// Checksums
// ---------------------------------------------------------------------------

/// UK NHS number — 10 digits, weighted mod-11 check digit.
pub fn validate_nhs(text: &str) -> Option<bool> {
    let d = digits(text);
    if d.len() != 10 {
        return Some(false);
    }
    let sum: u32 = (0..9).map(|i| d[i] as u32 * (10 - i as u32)).sum();
    let check = 11 - (sum % 11);
    let check = match check {
        11 => 0,
        10 => return Some(false),
        c => c,
    };
    Some(check == d[9] as u32)
}

/// Spanish NIF/DNI — 8 digits + control letter from a fixed table.
pub fn validate_es_nif(text: &str) -> Option<bool> {
    const TABLE: &[u8; 23] = b"TRWAGMYFPDXBNJZSQVHLCKE";
    let up: String = text.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    if up.len() != 9 {
        return Some(false);
    }
    let num: u32 = up[0..8].parse().ok()?;
    let letter = up.as_bytes()[8].to_ascii_uppercase();
    Some(TABLE[(num % 23) as usize] == letter)
}

/// Polish PESEL — 11 digits, weighted mod-10 check digit.
pub fn validate_pesel(text: &str) -> Option<bool> {
    let d = digits(text);
    if d.len() != 11 {
        return Some(false);
    }
    const W: [u32; 10] = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3];
    let sum: u32 = (0..10).map(|i| d[i] as u32 * W[i]).sum();
    let check = (10 - (sum % 10)) % 10;
    Some(check == d[10] as u32)
}

/// Singapore NRIC/FIN — prefix letter + 7 digits + weighted check letter.
pub fn validate_sg_nric(text: &str) -> Option<bool> {
    let up: String = text
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if up.len() != 9 {
        return Some(false);
    }
    let bytes = up.as_bytes();
    let prefix = bytes[0];
    let d = digits(&up[1..8]);
    if d.len() != 7 {
        return Some(false);
    }
    const W: [u32; 7] = [2, 7, 6, 5, 4, 3, 2];
    let mut sum: u32 = (0..7).map(|i| d[i] as u32 * W[i]).sum();
    if prefix == b'T' || prefix == b'G' {
        sum += 4;
    }
    let r = (sum % 11) as usize;
    let table: &[u8] = match prefix {
        b'S' | b'T' => b"JZIHGFEDCBA",
        b'F' | b'G' => b"XWUTRQPNMLK",
        _ => return Some(false),
    };
    Some(table[r] == bytes[8])
}

/// Australian Business Number — 11 digits, weighted mod-89.
pub fn validate_au_abn(text: &str) -> Option<bool> {
    let mut d = digits(text);
    if d.len() != 11 {
        return Some(false);
    }
    const W: [u32; 11] = [10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19];
    d[0] = d[0].wrapping_sub(1); // subtract 1 from the first digit
    let sum: u32 = (0..11).map(|i| d[i] as u32 * W[i]).sum();
    Some(sum.is_multiple_of(89))
}

/// Australian Tax File Number — 9 digits, weighted mod-11.
pub fn validate_au_tfn(text: &str) -> Option<bool> {
    let d = digits(text);
    if d.len() != 9 {
        return Some(false);
    }
    const W: [u32; 9] = [1, 4, 3, 7, 5, 8, 6, 9, 10];
    let sum: u32 = (0..9).map(|i| d[i] as u32 * W[i]).sum();
    Some(sum.is_multiple_of(11))
}

/// Indian Aadhaar — 12 digits with a trailing Verhoeff check digit.
pub fn validate_aadhaar(text: &str) -> Option<bool> {
    let d = digits(text);
    if d.len() != 12 || d[0] < 2 {
        return Some(false);
    }
    Some(verhoeff_valid(&d))
}

/// Finnish personal identity code — ddmmyy + sign + 3 digits + control char.
pub fn validate_fi_hetu(text: &str) -> Option<bool> {
    const TABLE: &[u8; 31] = b"0123456789ABCDEFHJKLMNPRSTUVWXY";
    let up: String = text.trim().to_ascii_uppercase();
    let raw: Vec<char> = up.chars().collect();
    if raw.len() != 11 {
        return Some(false);
    }
    let dm: String = raw[0..6].iter().collect();
    let sign = raw[6];
    let indiv: String = raw[7..10].iter().collect();
    let control = raw[10] as u8;
    if !matches!(sign, '+' | '-' | 'A') {
        return Some(false);
    }
    let (Ok(dm), Ok(indiv)) = (dm.parse::<u64>(), indiv.parse::<u64>()) else {
        return Some(false);
    };
    let n = dm * 1000 + indiv;
    Some(TABLE[(n % 31) as usize] == control)
}

// Verhoeff algorithm tables (dihedral group D5).
const VERHOEFF_D: [[usize; 10]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];
const VERHOEFF_P: [[usize; 10]; 8] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

fn verhoeff_valid(d: &[u8]) -> bool {
    let mut c = 0usize;
    for (i, &digit) in d.iter().rev().enumerate() {
        c = VERHOEFF_D[c][VERHOEFF_P[i % 8][digit as usize]];
    }
    c == 0
}

const NIF_TABLE: &[u8; 23] = b"TRWAGMYFPDXBNJZSQVHLCKE";

/// Spanish NIE — X/Y/Z + 7 digits + control letter (X/Y/Z map to 0/1/2).
pub fn validate_es_nie(text: &str) -> Option<bool> {
    let up: String = text
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if up.len() != 9 {
        return Some(false);
    }
    let lead = match up.as_bytes()[0] {
        b'X' => '0',
        b'Y' => '1',
        b'Z' => '2',
        _ => return Some(false),
    };
    let numstr: String = format!("{}{}", lead, &up[1..8]);
    let num: u32 = numstr.parse().ok()?;
    Some(NIF_TABLE[(num % 23) as usize] == up.as_bytes()[8])
}

/// Australian Company Number — 9 digits, weighted complement-mod-10 check.
pub fn validate_au_acn(text: &str) -> Option<bool> {
    let d = digits(text);
    if d.len() != 9 {
        return Some(false);
    }
    const W: [u32; 8] = [8, 7, 6, 5, 4, 3, 2, 1];
    let sum: u32 = (0..8).map(|i| d[i] as u32 * W[i]).sum();
    let check = (10 - (sum % 10)) % 10;
    Some(check == d[8] as u32)
}

/// Australian Medicare number — 10 digits, 9th is a weighted check of the first 8.
pub fn validate_au_medicare(text: &str) -> Option<bool> {
    let d = digits(text);
    if d.len() != 10 || !(2..=6).contains(&d[0]) {
        return Some(false);
    }
    const W: [u32; 8] = [1, 3, 7, 9, 1, 3, 7, 9];
    let sum: u32 = (0..8).map(|i| d[i] as u32 * W[i]).sum();
    Some(sum % 10 == d[8] as u32)
}

/// Italian VAT (Partita IVA) — 11 digits, Luhn-style mod-10.
pub fn validate_it_vat(text: &str) -> Option<bool> {
    let d = digits(text);
    if d.len() != 11 {
        return Some(false);
    }
    let mut sum = 0u32;
    for (i, &digit) in d.iter().enumerate() {
        if i % 2 == 0 {
            sum += digit as u32;
        } else {
            let mut v = digit as u32 * 2;
            if v > 9 {
                v -= 9;
            }
            sum += v;
        }
    }
    Some(sum.is_multiple_of(10))
}

/// Canadian Social Insurance Number — 9 digits, Luhn.
pub fn validate_ca_sin(text: &str) -> Option<bool> {
    let d: String = text.chars().filter(|c| c.is_ascii_digit()).collect();
    if d.len() != 9 {
        return Some(false);
    }
    Some(crate::validators::luhn_valid(&d))
}

fn cpf_check(slice: &[u8]) -> u8 {
    let n = slice.len();
    let sum: u32 = slice
        .iter()
        .enumerate()
        .map(|(i, &x)| x as u32 * ((n + 1 - i) as u32))
        .sum();
    let r = (sum * 10) % 11;
    if r == 10 {
        0
    } else {
        r as u8
    }
}

/// Brazilian CPF — 11 digits, two mod-11 check digits.
pub fn validate_br_cpf(text: &str) -> Option<bool> {
    let d = digits(text);
    if d.len() != 11 || d.iter().all(|&x| x == d[0]) {
        return Some(false);
    }
    if cpf_check(&d[0..9]) != d[9] {
        return Some(false);
    }
    Some(cpf_check(&d[0..10]) == d[10])
}

fn cnpj_check(d: &[u8], weights: &[u32]) -> u8 {
    let sum: u32 = d.iter().zip(weights).map(|(&x, &w)| x as u32 * w).sum();
    let r = sum % 11;
    if r < 2 {
        0
    } else {
        (11 - r) as u8
    }
}

/// Brazilian CNPJ — 14 digits, two mod-11 check digits.
pub fn validate_br_cnpj(text: &str) -> Option<bool> {
    let d = digits(text);
    if d.len() != 14 || d.iter().all(|&x| x == d[0]) {
        return Some(false);
    }
    const W1: [u32; 12] = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
    const W2: [u32; 13] = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
    if cnpj_check(&d[0..12], &W1) != d[12] {
        return Some(false);
    }
    Some(cnpj_check(&d[0..13], &W2) == d[13])
}

/// Dutch BSN — 9 digits, "eleven-test".
pub fn validate_nl_bsn(text: &str) -> Option<bool> {
    let d = digits(text);
    if d.len() != 9 {
        return Some(false);
    }
    const W: [i32; 9] = [9, 8, 7, 6, 5, 4, 3, 2, -1];
    let sum: i32 = (0..9).map(|i| d[i] as i32 * W[i]).sum();
    Some(sum % 11 == 0)
}

/// Turkish T.C. Kimlik No — 11 digits, two check digits.
pub fn validate_tr_tckn(text: &str) -> Option<bool> {
    let d = digits(text);
    if d.len() != 11 || d[0] == 0 {
        return Some(false);
    }
    let odd = (d[0] + d[2] + d[4] + d[6] + d[8]) as i32;
    let even = (d[1] + d[3] + d[5] + d[7]) as i32;
    let c10 = (7 * odd - even).rem_euclid(10) as u8;
    if c10 != d[9] {
        return Some(false);
    }
    let s: u32 = (0..10).map(|i| d[i] as u32).sum();
    Some((s % 10) as u8 == d[10])
}

/// Belgian National Register Number — 11 digits, mod-97 (pre/post 2000).
pub fn validate_be_nrn(text: &str) -> Option<bool> {
    let d = digits(text);
    if d.len() != 11 {
        return Some(false);
    }
    let first9: u64 = d[0..9].iter().fold(0u64, |a, &x| a * 10 + x as u64);
    let check = d[9] as u64 * 10 + d[10] as u64;
    let c1 = 97 - (first9 % 97);
    let c2 = 97 - ((2_000_000_000u64 + first9) % 97);
    Some(check == c1 || check == c2)
}

/// Portuguese NIF — 9 digits, mod-11.
pub fn validate_pt_nif(text: &str) -> Option<bool> {
    let d = digits(text);
    if d.len() != 9 {
        return Some(false);
    }
    let sum: u32 = (0..8).map(|i| d[i] as u32 * (9 - i as u32)).sum();
    let r = sum % 11;
    let mut check = 11 - r;
    if check >= 10 {
        check = 0;
    }
    Some(check == d[8] as u32)
}

/// Chinese Resident Identity Card — 18 chars, ISO 7064 MOD 11-2 (last may be X).
pub fn validate_cn_ric(text: &str) -> Option<bool> {
    let up: String = text
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if up.len() != 18 {
        return Some(false);
    }
    const W: [u32; 17] = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
    let bytes = up.as_bytes();
    let mut sum = 0u32;
    for i in 0..17 {
        match (bytes[i] as char).to_digit(10) {
            Some(v) => sum += v * W[i],
            None => return Some(false),
        }
    }
    let check = (12 - (sum % 11)) % 11;
    let expected = if check == 10 {
        b'X'
    } else {
        b'0' + check as u8
    };
    Some(expected == bytes[17])
}

/// Russian SNILS — 11 digits, weighted mod-101.
pub fn validate_ru_snils(text: &str) -> Option<bool> {
    let d = digits(text);
    if d.len() != 11 {
        return Some(false);
    }
    let sum: u32 = (0..9).map(|i| d[i] as u32 * (9 - i as u32)).sum();
    let mut check = sum % 101;
    if check == 100 {
        check = 0;
    }
    Some(check == d[9] as u32 * 10 + d[10] as u32)
}

/// German tax ID (Steuer-IdNr) — 11 digits, iterative product/sum check.
pub fn validate_de_tax(text: &str) -> Option<bool> {
    let d = digits(text);
    if d.len() != 11 {
        return Some(false);
    }
    let mut product = 10u32;
    for &digit in d.iter().take(10) {
        let mut sum = (digit as u32 + product) % 10;
        if sum == 0 {
            sum = 10;
        }
        product = (sum * 2) % 11;
    }
    let check = (11 - product) % 10;
    Some(check == d[10] as u32)
}

/// Swedish personnummer — Luhn over the 10-digit form.
pub fn validate_se_pnr(text: &str) -> Option<bool> {
    let dd: String = text.chars().filter(|c| c.is_ascii_digit()).collect();
    let s = if dd.len() == 12 {
        dd[2..].to_string()
    } else {
        dd
    };
    if s.len() != 10 {
        return Some(false);
    }
    Some(crate::validators::luhn_valid(&s))
}

/// South African ID number — 13 digits, Luhn.
pub fn validate_za_id(text: &str) -> Option<bool> {
    let dd: String = text.chars().filter(|c| c.is_ascii_digit()).collect();
    if dd.len() != 13 {
        return Some(false);
    }
    Some(crate::validators::luhn_valid(&dd))
}

/// Korean Resident Registration Number — 13 digits, weighted mod-11.
pub fn validate_kr_rrn(text: &str) -> Option<bool> {
    let d = digits(text);
    if d.len() != 13 {
        return Some(false);
    }
    const W: [u32; 12] = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5];
    let sum: u32 = (0..12).map(|i| d[i] as u32 * W[i]).sum();
    let check = (11 - (sum % 11)) % 10;
    Some(check == d[12] as u32)
}

// ---------------------------------------------------------------------------
// Recognizers
// ---------------------------------------------------------------------------

fn p(name: &str, re: &str, score: f64) -> Pattern {
    Pattern::new(name, re, score)
}

pub fn uk_nhs() -> PatternRecognizer {
    PatternRecognizer::new(
        "NhsRecognizer",
        "UK_NHS",
        vec![p("NHS", r"\b\d{3}[ -]?\d{3}[ -]?\d{4}\b", 0.3)],
    )
    .with_validator(validate_nhs)
    .with_context(&["nhs", "health", "national", "service"])
}

pub fn uk_nino() -> PatternRecognizer {
    PatternRecognizer::new(
        "UkNinoRecognizer",
        "UK_NINO",
        vec![p(
            "NINO",
            r"\b[ABCEGHJ-PRSTW-Z][ABCEGHJ-NPRSTW-Z] ?\d{2} ?\d{2} ?\d{2} ?[A-D]\b",
            0.4,
        )],
    )
    .with_context(&["national", "insurance", "nino", "ni"])
}

pub fn es_nif() -> PatternRecognizer {
    PatternRecognizer::new(
        "EsNifRecognizer",
        "ES_NIF",
        vec![p("NIF", r"\b\d{8}[A-HJ-NP-TV-Za-hj-np-tv-z]\b", 0.3)],
    )
    .with_validator(validate_es_nif)
    .with_context(&["nif", "dni", "documento", "identidad"])
}

pub fn pl_pesel() -> PatternRecognizer {
    PatternRecognizer::new(
        "PlPeselRecognizer",
        "PL_PESEL",
        vec![p("PESEL", r"\b\d{11}\b", 0.1)],
    )
    .with_validator(validate_pesel)
    .with_context(&["pesel"])
}

pub fn sg_nric() -> PatternRecognizer {
    PatternRecognizer::new(
        "SgNricRecognizer",
        "SG_NRIC_FIN",
        vec![p("NRIC", r"\b[STFGstfg]\d{7}[A-Za-z]\b", 0.3)],
    )
    .with_validator(validate_sg_nric)
    .with_context(&["nric", "fin", "identity"])
}

pub fn au_abn() -> PatternRecognizer {
    PatternRecognizer::new(
        "AuAbnRecognizer",
        "AU_ABN",
        vec![p("ABN", r"\b\d{2} ?\d{3} ?\d{3} ?\d{3}\b", 0.1)],
    )
    .with_validator(validate_au_abn)
    .with_context(&["abn", "australian", "business", "number"])
}

pub fn au_tfn() -> PatternRecognizer {
    PatternRecognizer::new(
        "AuTfnRecognizer",
        "AU_TFN",
        vec![p("TFN", r"\b\d{3} ?\d{3} ?\d{3}\b", 0.1)],
    )
    .with_validator(validate_au_tfn)
    .with_context(&["tfn", "tax", "file", "number"])
}

pub fn in_aadhaar() -> PatternRecognizer {
    PatternRecognizer::new(
        "InAadhaarRecognizer",
        "IN_AADHAAR",
        vec![p("Aadhaar", r"\b[2-9]\d{3} ?\d{4} ?\d{4}\b", 0.1)],
    )
    .with_validator(validate_aadhaar)
    .with_context(&["aadhaar", "uid", "uidai"])
}

pub fn in_pan() -> PatternRecognizer {
    PatternRecognizer::new(
        "InPanRecognizer",
        "IN_PAN",
        vec![p("PAN", r"\b[A-Za-z]{5}\d{4}[A-Za-z]\b", 0.3)],
    )
    .with_context(&["pan", "permanent", "account"])
}

pub fn it_fiscal_code() -> PatternRecognizer {
    PatternRecognizer::new(
        "ItFiscalCodeRecognizer",
        "IT_FISCAL_CODE",
        vec![p(
            "CF",
            r"\b[A-Za-z]{6}\d{2}[A-Za-z]\d{2}[A-Za-z]\d{3}[A-Za-z]\b",
            0.3,
        )],
    )
    .with_context(&["codice", "fiscale", "fiscal", "code"])
}

pub fn fi_hetu() -> PatternRecognizer {
    PatternRecognizer::new(
        "FiHetuRecognizer",
        "FI_PERSONAL_IDENTITY_CODE",
        vec![p("HETU", r"\b\d{6}[-+ABCDEFYXWVU]\d{3}[0-9A-Ya-y]\b", 0.3)],
    )
    .with_validator(validate_fi_hetu)
    .with_context(&["hetu", "henkilotunnus", "identity"])
}

pub fn us_itin() -> PatternRecognizer {
    PatternRecognizer::new(
        "UsItinRecognizer",
        "US_ITIN",
        vec![p("ITIN", r"\b9\d{2}[- ]?\d{2}[- ]?\d{4}\b", 0.3)],
    )
    .with_context(&["itin", "taxpayer", "individual", "tax"])
}

pub fn es_nie() -> PatternRecognizer {
    PatternRecognizer::new(
        "EsNieRecognizer",
        "ES_NIE",
        vec![p("NIE", r"\b[XYZxyz]\d{7}[A-Za-z]\b", 0.3)],
    )
    .with_validator(validate_es_nie)
    .with_context(&["nie", "extranjero", "identidad"])
}

pub fn au_acn() -> PatternRecognizer {
    PatternRecognizer::new(
        "AuAcnRecognizer",
        "AU_ACN",
        vec![p("ACN", r"\b\d{3} ?\d{3} ?\d{3}\b", 0.1)],
    )
    .with_validator(validate_au_acn)
    .with_context(&["acn", "company", "australian"])
}

pub fn au_medicare() -> PatternRecognizer {
    PatternRecognizer::new(
        "AuMedicareRecognizer",
        "AU_MEDICARE",
        vec![p("Medicare", r"\b[2-6]\d{3} ?\d{5} ?\d\b", 0.1)],
    )
    .with_validator(validate_au_medicare)
    .with_context(&["medicare"])
}

pub fn it_vat_code() -> PatternRecognizer {
    PatternRecognizer::new(
        "ItVatRecognizer",
        "IT_VAT_CODE",
        vec![p("VAT", r"\b\d{11}\b", 0.1)],
    )
    .with_validator(validate_it_vat)
    .with_context(&["vat", "iva", "partita"])
}

pub fn ca_sin() -> PatternRecognizer {
    PatternRecognizer::new(
        "CaSinRecognizer",
        "CA_SIN",
        vec![p("SIN", r"\b\d{3} ?\d{3} ?\d{3}\b", 0.1)],
    )
    .with_validator(validate_ca_sin)
    .with_context(&["sin", "social", "insurance"])
}

pub fn it_driver_license() -> PatternRecognizer {
    PatternRecognizer::new(
        "ItDriverLicenseRecognizer",
        "IT_DRIVER_LICENSE",
        vec![p("IT DL", r"\b[A-Za-z]{2}\d{7}[A-Za-z]\b", 0.3)],
    )
    .with_context(&["patente", "driver", "license", "licence"])
}

pub fn in_voter() -> PatternRecognizer {
    PatternRecognizer::new(
        "InVoterRecognizer",
        "IN_VOTER",
        vec![p("Voter ID", r"\b[A-Za-z]{3}\d{7}\b", 0.3)],
    )
    .with_context(&["voter", "epic", "election"])
}

pub fn in_passport() -> PatternRecognizer {
    PatternRecognizer::new(
        "InPassportRecognizer",
        "IN_PASSPORT",
        vec![p("IN Passport", r"\b[A-Za-z]\d{7}\b", 0.3)],
    )
    .with_context(&["passport"])
}

pub fn in_vehicle_registration() -> PatternRecognizer {
    PatternRecognizer::new(
        "InVehicleRegistrationRecognizer",
        "IN_VEHICLE_REGISTRATION",
        vec![p(
            "IN Vehicle",
            r"\b[A-Za-z]{2}\d{2}[A-Za-z]{1,2}\d{4}\b",
            0.3,
        )],
    )
    .with_context(&["vehicle", "registration", "number", "plate"])
}

pub fn sg_uen() -> PatternRecognizer {
    PatternRecognizer::new(
        "SgUenRecognizer",
        "SG_UEN",
        vec![p("UEN", r"\b\d{8,9}[A-Za-z]\b", 0.3)],
    )
    .with_context(&["uen", "entity", "business"])
}

/// US passport — weak (9 digits), leans on context.
pub fn us_passport() -> PatternRecognizer {
    PatternRecognizer::new(
        "UsPassportRecognizer",
        "US_PASSPORT",
        vec![p("US Passport", r"\b\d{9}\b", 0.05)],
    )
    .with_context(&["passport", "travel", "document"])
}

/// US driver license — weak, leans on context.
pub fn us_driver_license() -> PatternRecognizer {
    PatternRecognizer::new(
        "UsDriverLicenseRecognizer",
        "US_DRIVER_LICENSE",
        vec![p("US DL", r"\b[A-Za-z]\d{6,12}\b", 0.3)],
    )
    .with_context(&["driver", "license", "licence", "dl"])
}

/// US bank account — very weak (8–17 digits), leans on context.
pub fn us_bank_number() -> PatternRecognizer {
    PatternRecognizer::new(
        "UsBankRecognizer",
        "US_BANK_NUMBER",
        vec![p("US Bank", r"\b\d{8,17}\b", 0.05)],
    )
    .with_context(&["bank", "account", "acct", "routing", "checking", "savings"])
}

pub fn br_cpf() -> PatternRecognizer {
    PatternRecognizer::new(
        "BrCpfRecognizer",
        "BR_CPF",
        vec![p("CPF", r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b", 0.1)],
    )
    .with_validator(validate_br_cpf)
    .with_context(&["cpf"])
}

pub fn br_cnpj() -> PatternRecognizer {
    PatternRecognizer::new(
        "BrCnpjRecognizer",
        "BR_CNPJ",
        vec![p("CNPJ", r"\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b", 0.1)],
    )
    .with_validator(validate_br_cnpj)
    .with_context(&["cnpj"])
}

pub fn nl_bsn() -> PatternRecognizer {
    PatternRecognizer::new(
        "NlBsnRecognizer",
        "NL_BSN",
        vec![p("BSN", r"\b\d{9}\b", 0.1)],
    )
    .with_validator(validate_nl_bsn)
    .with_context(&["bsn", "burgerservicenummer"])
}

pub fn tr_tckn() -> PatternRecognizer {
    PatternRecognizer::new(
        "TrTcknRecognizer",
        "TR_TCKN",
        vec![p("TCKN", r"\b[1-9]\d{10}\b", 0.1)],
    )
    .with_validator(validate_tr_tckn)
    .with_context(&["tc", "kimlik", "tckn"])
}

pub fn be_nrn() -> PatternRecognizer {
    PatternRecognizer::new(
        "BeNrnRecognizer",
        "BE_NRN",
        vec![p("NRN", r"\b\d{2}\.?\d{2}\.?\d{2}-?\d{3}\.?\d{2}\b", 0.1)],
    )
    .with_validator(validate_be_nrn)
    .with_context(&["rijksregister", "niss", "nrn"])
}

pub fn pt_nif() -> PatternRecognizer {
    PatternRecognizer::new(
        "PtNifRecognizer",
        "PT_NIF",
        vec![p("PT NIF", r"\b\d{9}\b", 0.1)],
    )
    .with_validator(validate_pt_nif)
    .with_context(&["nif", "contribuinte"])
}

pub fn cn_ric() -> PatternRecognizer {
    PatternRecognizer::new(
        "CnRicRecognizer",
        "CN_RIC",
        vec![p("RIC", r"\b\d{17}[\dXx]\b", 0.1)],
    )
    .with_validator(validate_cn_ric)
    .with_context(&["身份证", "id"])
}

pub fn ru_snils() -> PatternRecognizer {
    PatternRecognizer::new(
        "RuSnilsRecognizer",
        "RU_SNILS",
        vec![p("SNILS", r"\b\d{3}-?\d{3}-?\d{3} ?\d{2}\b", 0.1)],
    )
    .with_validator(validate_ru_snils)
    .with_context(&["снилс", "snils"])
}

pub fn de_tax() -> PatternRecognizer {
    PatternRecognizer::new(
        "DeTaxRecognizer",
        "DE_TAX_ID",
        vec![p("Steuer-ID", r"\b\d{11}\b", 0.05)],
    )
    .with_validator(validate_de_tax)
    .with_context(&["steuer", "steueridentifikationsnummer", "tax"])
}

pub fn se_pnr() -> PatternRecognizer {
    PatternRecognizer::new(
        "SePnrRecognizer",
        "SE_PERSONNUMMER",
        vec![p("Personnummer", r"\b\d{6}[-+]?\d{4}\b", 0.1)],
    )
    .with_validator(validate_se_pnr)
    .with_context(&["personnummer"])
}

pub fn za_id() -> PatternRecognizer {
    PatternRecognizer::new(
        "ZaIdRecognizer",
        "ZA_ID",
        vec![p("ZA ID", r"\b\d{13}\b", 0.1)],
    )
    .with_validator(validate_za_id)
    .with_context(&["id", "identity"])
}

pub fn kr_rrn() -> PatternRecognizer {
    PatternRecognizer::new(
        "KrRrnRecognizer",
        "KR_RRN",
        vec![p("RRN", r"\b\d{6}-?\d{7}\b", 0.1)],
    )
    .with_validator(validate_kr_rrn)
    .with_context(&["주민", "rrn"])
}

/// Japanese My Number — 12 digits (pattern; context-gated).
pub fn jp_mynumber() -> PatternRecognizer {
    PatternRecognizer::new(
        "JpMyNumberRecognizer",
        "JP_MYNUMBER",
        vec![p("My Number", r"\b\d{4} ?\d{4} ?\d{4}\b", 0.1)],
    )
    .with_context(&["mynumber", "個人番号", "マイナンバー"])
}

/// Mexican RFC — pattern.
pub fn mx_rfc() -> PatternRecognizer {
    PatternRecognizer::new(
        "MxRfcRecognizer",
        "MX_RFC",
        vec![p("RFC", r"\b[A-Za-z]{4}\d{6}[A-Za-z0-9]{3}\b", 0.3)],
    )
    .with_context(&["rfc"])
}

/// Mexican CURP — pattern.
pub fn mx_curp() -> PatternRecognizer {
    PatternRecognizer::new(
        "MxCurpRecognizer",
        "MX_CURP",
        vec![p(
            "CURP",
            r"\b[A-Za-z]{4}\d{6}[A-Za-z]{6}[A-Za-z0-9]\d\b",
            0.3,
        )],
    )
    .with_context(&["curp"])
}

/// Every country-specific recognizer, ready to register.
pub fn all_country() -> Vec<Box<dyn EntityRecognizer>> {
    vec![
        Box::new(uk_nhs()),
        Box::new(uk_nino()),
        Box::new(es_nif()),
        Box::new(es_nie()),
        Box::new(pl_pesel()),
        Box::new(sg_nric()),
        Box::new(sg_uen()),
        Box::new(au_abn()),
        Box::new(au_tfn()),
        Box::new(au_acn()),
        Box::new(au_medicare()),
        Box::new(in_aadhaar()),
        Box::new(in_pan()),
        Box::new(in_voter()),
        Box::new(in_passport()),
        Box::new(in_vehicle_registration()),
        Box::new(it_fiscal_code()),
        Box::new(it_vat_code()),
        Box::new(it_driver_license()),
        Box::new(fi_hetu()),
        Box::new(ca_sin()),
        Box::new(us_itin()),
        Box::new(us_passport()),
        Box::new(us_driver_license()),
        Box::new(us_bank_number()),
        // International (checksummed where a check digit exists).
        Box::new(br_cpf()),
        Box::new(br_cnpj()),
        Box::new(nl_bsn()),
        Box::new(tr_tckn()),
        Box::new(be_nrn()),
        Box::new(pt_nif()),
        Box::new(cn_ric()),
        Box::new(ru_snils()),
        Box::new(de_tax()),
        Box::new(se_pnr()),
        Box::new(za_id()),
        Box::new(kr_rrn()),
        Box::new(jp_mynumber()),
        Box::new(mx_rfc()),
        Box::new(mx_curp()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nhs() {
        assert_eq!(validate_nhs("943 476 5919"), Some(true));
        assert_eq!(validate_nhs("943 476 5918"), Some(false));
        assert_eq!(validate_nhs("12345"), Some(false));
    }

    #[test]
    fn es_nif_check() {
        assert_eq!(validate_es_nif("12345678Z"), Some(true));
        assert_eq!(validate_es_nif("12345678A"), Some(false));
        assert_eq!(validate_es_nif("1234"), Some(false));
    }

    #[test]
    fn pesel_check() {
        assert_eq!(validate_pesel("44051401359"), Some(true));
        assert_eq!(validate_pesel("44051401358"), Some(false));
        assert_eq!(validate_pesel("123"), Some(false));
    }

    #[test]
    fn sg_nric_check() {
        assert_eq!(validate_sg_nric("S1234567D"), Some(true));
        assert_eq!(validate_sg_nric("S1234567A"), Some(false));
        assert_eq!(validate_sg_nric("Z1234567D"), Some(false));
        assert_eq!(validate_sg_nric("bad"), Some(false));
    }

    #[test]
    fn au_checks() {
        assert_eq!(validate_au_abn("51 824 753 556"), Some(true));
        assert_eq!(validate_au_abn("51 824 753 557"), Some(false));
        assert_eq!(validate_au_abn("1"), Some(false));
        assert_eq!(validate_au_tfn("123456782"), Some(true));
        assert_eq!(validate_au_tfn("123456783"), Some(false));
        assert_eq!(validate_au_tfn("12"), Some(false));
    }

    #[test]
    fn aadhaar_verhoeff() {
        assert_eq!(validate_aadhaar("999941057058"), Some(true));
        assert_eq!(validate_aadhaar("999941057059"), Some(false));
        assert_eq!(validate_aadhaar("123"), Some(false));
    }

    #[test]
    fn fi_hetu_check() {
        assert_eq!(validate_fi_hetu("131052-308T"), Some(true));
        assert_eq!(validate_fi_hetu("131052-308U"), Some(false));
        assert_eq!(validate_fi_hetu("131052X308T"), Some(false));
        assert_eq!(validate_fi_hetu("bad"), Some(false));
    }

    #[test]
    fn es_nie_check() {
        assert_eq!(validate_es_nie("X1234567L"), Some(true));
        assert_eq!(validate_es_nie("X1234567A"), Some(false));
        assert_eq!(validate_es_nie("A1234567L"), Some(false)); // bad prefix
        assert_eq!(validate_es_nie("bad"), Some(false));
    }

    #[test]
    fn au_acn_check() {
        assert_eq!(validate_au_acn("004 085 616"), Some(true));
        assert_eq!(validate_au_acn("004 085 617"), Some(false));
        assert_eq!(validate_au_acn("1"), Some(false));
    }

    #[test]
    fn au_medicare_check() {
        assert_eq!(validate_au_medicare("2428778132"), Some(true));
        assert_eq!(validate_au_medicare("2428778142"), Some(false));
        assert_eq!(validate_au_medicare("9428778132"), Some(false)); // bad first digit
        assert_eq!(validate_au_medicare("123"), Some(false));
    }

    #[test]
    fn it_vat_check() {
        assert_eq!(validate_it_vat("12345670785"), Some(true));
        assert_eq!(validate_it_vat("12345670786"), Some(false));
        assert_eq!(validate_it_vat("123"), Some(false));
    }

    #[test]
    fn ca_sin_check() {
        assert_eq!(validate_ca_sin("046 454 286"), Some(true));
        assert_eq!(validate_ca_sin("046 454 287"), Some(false));
        assert_eq!(validate_ca_sin("12"), Some(false));
    }

    #[test]
    fn br_cpf_check() {
        assert_eq!(validate_br_cpf("111.444.777-35"), Some(true));
        assert_eq!(validate_br_cpf("111.444.777-36"), Some(false));
        assert_eq!(validate_br_cpf("111.111.111-11"), Some(false)); // all-equal
        assert_eq!(validate_br_cpf("123"), Some(false));
    }

    #[test]
    fn br_cnpj_check() {
        assert_eq!(validate_br_cnpj("11.222.333/0001-81"), Some(true));
        assert_eq!(validate_br_cnpj("11.222.333/0001-82"), Some(false));
        assert_eq!(validate_br_cnpj("1"), Some(false));
    }

    #[test]
    fn nl_bsn_check() {
        assert_eq!(validate_nl_bsn("111222333"), Some(true));
        assert_eq!(validate_nl_bsn("111222334"), Some(false));
        assert_eq!(validate_nl_bsn("12"), Some(false));
    }

    #[test]
    fn tr_tckn_check() {
        assert_eq!(validate_tr_tckn("10000000146"), Some(true));
        assert_eq!(validate_tr_tckn("10000000147"), Some(false));
        assert_eq!(validate_tr_tckn("00000000146"), Some(false));
    }

    #[test]
    fn be_nrn_check() {
        assert_eq!(validate_be_nrn("93051822361"), Some(true));
        assert_eq!(validate_be_nrn("93051822362"), Some(false));
        assert_eq!(validate_be_nrn("1"), Some(false));
    }

    #[test]
    fn pt_nif_check() {
        assert_eq!(validate_pt_nif("123456789"), Some(true));
        assert_eq!(validate_pt_nif("123456781"), Some(false));
        assert_eq!(validate_pt_nif("12"), Some(false));
    }

    #[test]
    fn cn_ric_check() {
        assert_eq!(validate_cn_ric("440524188001010014"), Some(true));
        assert_eq!(validate_cn_ric("440524188001010015"), Some(false));
        assert_eq!(validate_cn_ric("123"), Some(false));
    }

    #[test]
    fn ru_snils_check() {
        assert_eq!(validate_ru_snils("11223344595"), Some(true));
        assert_eq!(validate_ru_snils("11223344596"), Some(false));
        assert_eq!(validate_ru_snils("1"), Some(false));
    }

    #[test]
    fn de_tax_check() {
        assert_eq!(validate_de_tax("86095742719"), Some(true));
        assert_eq!(validate_de_tax("86095742718"), Some(false));
        assert_eq!(validate_de_tax("12"), Some(false));
    }

    #[test]
    fn se_pnr_check() {
        assert_eq!(validate_se_pnr("8112189876"), Some(true));
        assert_eq!(validate_se_pnr("8112189875"), Some(false));
        assert_eq!(validate_se_pnr("198112189876"), Some(true));
        assert_eq!(validate_se_pnr("12"), Some(false));
    }

    #[test]
    fn za_id_check() {
        assert_eq!(validate_za_id("8001015009087"), Some(true));
        assert_eq!(validate_za_id("8001015009088"), Some(false));
        assert_eq!(validate_za_id("12"), Some(false));
    }

    #[test]
    fn kr_rrn_check() {
        assert_eq!(validate_kr_rrn("9412011234569"), Some(true));
        assert_eq!(validate_kr_rrn("9412011234568"), Some(false));
        assert_eq!(validate_kr_rrn("12"), Some(false));
    }
}
