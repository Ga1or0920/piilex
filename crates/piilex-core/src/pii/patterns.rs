use regex::Regex;
use std::sync::LazyLock;

use crate::finding::PiiType;

pub struct LiteralPattern {
    pub pii_type: PiiType,
    pub regex: &'static LazyLock<Regex>,
    pub description: &'static str,
}

static EMAIL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"#).unwrap());

static IPV4_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"#).unwrap()
});

static CREDIT_CARD_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"#).unwrap()
});

// My Number (Japan Individual Number): 12 digits, optionally space-separated
static MY_NUMBER_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\b[0-9]{4}\s?[0-9]{4}\s?[0-9]{4}\b"#).unwrap());

// IBAN: 2-letter country + 2 check digits + up to 30 alphanumeric
static IBAN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}(?:[A-Z0-9]{0,18})\b"#).unwrap()
});

pub fn builtin_literal_patterns() -> Vec<LiteralPattern> {
    vec![
        LiteralPattern {
            pii_type: PiiType::Email,
            regex: &EMAIL_RE,
            description: "email address literal",
        },
        LiteralPattern {
            pii_type: PiiType::IpAddress,
            regex: &IPV4_RE,
            description: "IPv4 address literal",
        },
        LiteralPattern {
            pii_type: PiiType::CreditCard,
            regex: &CREDIT_CARD_RE,
            description: "credit card number literal",
        },
        LiteralPattern {
            pii_type: PiiType::MyNumber,
            regex: &MY_NUMBER_RE,
            description: "Japan Individual Number (My Number) literal",
        },
        LiteralPattern {
            pii_type: PiiType::Iban,
            regex: &IBAN_RE,
            description: "IBAN literal",
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_regex_matches() {
        assert!(EMAIL_RE.is_match("user@example.com"));
        assert!(EMAIL_RE.is_match("test.user+tag@domain.co.jp"));
        assert!(!EMAIL_RE.is_match("not-an-email"));
    }

    #[test]
    fn ipv4_regex_matches() {
        assert!(IPV4_RE.is_match("192.168.1.1"));
        assert!(IPV4_RE.is_match("10.0.0.1"));
        assert!(!IPV4_RE.is_match("999.999.999.999"));
    }

    #[test]
    fn credit_card_regex_matches() {
        assert!(CREDIT_CARD_RE.is_match("4111111111111111"));
        assert!(CREDIT_CARD_RE.is_match("5500000000000004"));
        assert!(!CREDIT_CARD_RE.is_match("1234567890"));
    }

    #[test]
    fn my_number_regex_matches() {
        assert!(MY_NUMBER_RE.is_match("1234 5678 9012"));
        assert!(MY_NUMBER_RE.is_match("123456789012"));
        assert!(!MY_NUMBER_RE.is_match("12345"));
    }

    #[test]
    fn iban_regex_matches() {
        assert!(IBAN_RE.is_match("DE89370400440532013000"));
        assert!(IBAN_RE.is_match("GB29NWBK60161331926819"));
        assert!(IBAN_RE.is_match("NL91ABNA0417164300"));
        assert!(!IBAN_RE.is_match("12345"));
    }
}
