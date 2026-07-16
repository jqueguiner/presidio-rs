//! Predefined recognizers.
//!
//! Rust ports of the recognizers under
//! `presidio_analyzer/predefined_recognizers/{generic,country_specific}`.
//! Regexes are adapted to the `regex` crate (no look-around) but keep Presidio's
//! entity names, base scores, checksum validators and context words.

use crate::pattern::Pattern;
use crate::recognizer::{EntityRecognizer, PatternRecognizer};
use crate::validators;

fn p(name: &str, re: &str, score: f64) -> Pattern {
    Pattern::new(name, re, score)
}

/// CREDIT_CARD — matches the major card layouts, promoted to 1.0 by Luhn.
pub fn credit_card() -> PatternRecognizer {
    PatternRecognizer::new(
        "CreditCardRecognizer",
        "CREDIT_CARD",
        vec![p(
            "All Credit Cards (weak)",
            r"\b((4\d{3})|(5[0-5]\d{2})|(6\d{3})|(1\d{3})|(3\d{3}))[- ]?(\d{3,4})[- ]?(\d{3,4})[- ]?(\d{3,5})\b",
            0.3,
        )],
    )
    .with_validator(validators::validate_credit_card)
    .with_context(&[
        "credit", "card", "visa", "mastercard", "amex", "discover", "diners", "maestro", "jcb",
        "cc", "instapayment",
    ])
}

/// CRYPTO — Bitcoin address, promoted to 1.0 by Base58Check.
pub fn crypto() -> PatternRecognizer {
    PatternRecognizer::new(
        "CryptoRecognizer",
        "CRYPTO",
        vec![p(
            "BTC address",
            r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,39}\b",
            0.5,
        )],
    )
    .with_validator(validators::validate_btc)
    .with_context(&["wallet", "btc", "bitcoin", "crypto", "address"])
}

/// EMAIL_ADDRESS.
pub fn email() -> PatternRecognizer {
    PatternRecognizer::new(
        "EmailRecognizer",
        "EMAIL_ADDRESS",
        vec![p(
            "Email (medium)",
            r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b",
            0.5,
        )],
    )
    .with_context(&["email", "mail", "e-mail"])
}

/// IBAN_CODE — generic layout, promoted to 1.0 by mod-97.
pub fn iban() -> PatternRecognizer {
    PatternRecognizer::new(
        "IbanRecognizer",
        "IBAN_CODE",
        vec![p(
            "IBAN Generic",
            r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}\b",
            0.3,
        )],
    )
    .with_validator(validators::validate_iban)
    .with_context(&["iban", "bank", "account", "transfer", "swift"])
}

/// IP_ADDRESS — IPv4 and (simplified) IPv6.
pub fn ip_address() -> PatternRecognizer {
    PatternRecognizer::new(
        "IpRecognizer",
        "IP_ADDRESS",
        vec![
            p(
                "IPv4",
                r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b",
                0.6,
            ),
            p("IPv6", r"\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b", 0.6),
        ],
    )
    .with_context(&["ip", "address", "ipv4", "ipv6"])
}

/// MAC_ADDRESS.
pub fn mac_address() -> PatternRecognizer {
    PatternRecognizer::new(
        "MacRecognizer",
        "MAC_ADDRESS",
        vec![p(
            "MAC",
            r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b",
            0.7,
        )],
    )
    .with_context(&["mac", "address"])
}

/// URL.
pub fn url() -> PatternRecognizer {
    PatternRecognizer::new(
        "UrlRecognizer",
        "URL",
        vec![p(
            "URL",
            r"(?:https?://|www\.)[A-Za-z0-9._~:/?#@!$&'()*+,;=%\-\[\]]+",
            0.6,
        )],
    )
    .with_context(&["url", "link", "website", "site"])
}

/// DATE_TIME — numeric and ISO dates.
pub fn date_time() -> PatternRecognizer {
    PatternRecognizer::new(
        "DateRecognizer",
        "DATE_TIME",
        vec![
            p(
                "Numeric date",
                r"\b\d{1,2}[/\-.]\d{1,2}[/\-.]\d{2,4}\b",
                0.6,
            ),
            p("ISO date", r"\b\d{4}-\d{2}-\d{2}\b", 0.6),
        ],
    )
    .with_context(&["date", "born", "birthday", "day", "year"])
}

/// US_SSN.
pub fn us_ssn() -> PatternRecognizer {
    PatternRecognizer::new(
        "UsSsnRecognizer",
        "US_SSN",
        vec![p("SSN", r"\b[0-9]{3}[-. ]?[0-9]{2}[-. ]?[0-9]{4}\b", 0.4)],
    )
    .with_validator(validators::validate_us_ssn)
    .with_context(&["social", "security", "ssn", "ssns", "ssid"])
}

/// All generic + country-specific pattern recognizers for English.
pub fn all_english() -> Vec<Box<dyn EntityRecognizer>> {
    vec![
        Box::new(credit_card()),
        Box::new(crypto()),
        Box::new(email()),
        Box::new(iban()),
        Box::new(ip_address()),
        Box::new(mac_address()),
        Box::new(url()),
        Box::new(date_time()),
        Box::new(us_ssn()),
    ]
}
