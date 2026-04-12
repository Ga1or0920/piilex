use crate::finding::{Confidence, PiiCategory, PiiType};
use crate::severity::Severity;
use regex::Regex;

pub struct PiiDictionary {
    entries: Vec<DictionaryEntry>,
}

pub struct DictionaryEntry {
    pub pii_type: PiiType,
    pub patterns: Vec<IdentifierPattern>,
    pub default_severity: Severity,
    pub category: PiiCategory,
}

pub struct IdentifierPattern {
    pub regex: Regex,
    pub confidence: Confidence,
}

fn pat(pattern: &str, confidence: Confidence) -> IdentifierPattern {
    IdentifierPattern {
        regex: Regex::new(pattern).expect("invalid built-in PII pattern"),
        confidence,
    }
}

impl PiiDictionary {
    pub fn builtin() -> Self {
        Self {
            entries: vec![
                // ── Contact Info ──
                DictionaryEntry {
                    pii_type: PiiType::Email,
                    patterns: vec![
                        pat(r"(?i)^e[-_]?mail(_addr(ess)?)?$", Confidence::High),
                        pat(
                            r"(?i)^(user|customer|client|member|employee)[-_]?email$",
                            Confidence::High,
                        ),
                        pat(r"(?i)email", Confidence::Medium),
                    ],
                    default_severity: Severity::High,
                    category: PiiCategory::ContactInfo,
                },
                DictionaryEntry {
                    pii_type: PiiType::PhoneNumber,
                    patterns: vec![
                        pat(r"(?i)^phone[-_]?(number|num|no)?$", Confidence::High),
                        pat(
                            r"(?i)^(mobile|cell|tel|telephone)[-_]?(number|num|no)?$",
                            Confidence::High,
                        ),
                        pat(r"(?i)(phone|mobile|cell|tel)", Confidence::Medium),
                    ],
                    default_severity: Severity::High,
                    category: PiiCategory::ContactInfo,
                },
                DictionaryEntry {
                    pii_type: PiiType::Address,
                    patterns: vec![
                        pat(
                            r"(?i)^(street|home|mailing|billing|shipping)[-_]?addr(ess)?$",
                            Confidence::High,
                        ),
                        pat(r"(?i)^address[-_]?(line[-_]?[12])?$", Confidence::High),
                        pat(r"(?i)^postal[-_]?(code|zip)$", Confidence::Medium),
                    ],
                    default_severity: Severity::High,
                    category: PiiCategory::ContactInfo,
                },
                // ── Personal Attributes ──
                DictionaryEntry {
                    pii_type: PiiType::FullName,
                    patterns: vec![
                        pat(r"(?i)^full[-_]?name$", Confidence::High),
                        pat(
                            r"(?i)^(first|last|given|family|sur)[-_]?name$",
                            Confidence::High,
                        ),
                        pat(
                            r"(?i)^(user|customer|client|display)[-_]?name$",
                            Confidence::Medium,
                        ),
                        pat(r"(?i)^name$", Confidence::Low),
                    ],
                    default_severity: Severity::High,
                    category: PiiCategory::PersonalAttribute,
                },
                DictionaryEntry {
                    pii_type: PiiType::DateOfBirth,
                    patterns: vec![pat(
                        r"(?i)^(date[-_]?of[-_]?birth|dob|birth[-_]?date|birthday)$",
                        Confidence::High,
                    )],
                    default_severity: Severity::Medium,
                    category: PiiCategory::PersonalAttribute,
                },
                DictionaryEntry {
                    pii_type: PiiType::Gender,
                    patterns: vec![
                        pat(r"(?i)^gender$", Confidence::High),
                        pat(r"(?i)^sex$", Confidence::Medium),
                    ],
                    default_severity: Severity::Low,
                    category: PiiCategory::PersonalAttribute,
                },
                // ── Identifiers ──
                DictionaryEntry {
                    pii_type: PiiType::NationalId,
                    patterns: vec![
                        pat(
                            r"(?i)^(ssn|social[-_]?security[-_]?(number|num|no)?)$",
                            Confidence::High,
                        ),
                        pat(r"(?i)^(national[-_]?id|resident[-_]?id)$", Confidence::High),
                    ],
                    default_severity: Severity::Critical,
                    category: PiiCategory::GovernmentId,
                },
                DictionaryEntry {
                    pii_type: PiiType::PassportNumber,
                    patterns: vec![pat(
                        r"(?i)^passport[-_]?(number|num|no|id)?$",
                        Confidence::High,
                    )],
                    default_severity: Severity::Critical,
                    category: PiiCategory::PersonalAttribute,
                },
                // ── Network ──
                DictionaryEntry {
                    pii_type: PiiType::IpAddress,
                    patterns: vec![
                        pat(r"(?i)^ip[-_]?(addr(ess)?)?$", Confidence::High),
                        pat(
                            r"(?i)^(client|remote|source|src|user)[-_]?ip$",
                            Confidence::High,
                        ),
                        pat(r"(?i)^ip[-_]?v[46]$", Confidence::High),
                        pat(r"(?i)ip[-_]?addr", Confidence::Medium),
                    ],
                    default_severity: Severity::Medium,
                    category: PiiCategory::NetworkIdentifier,
                },
                // ── Financial ──
                DictionaryEntry {
                    pii_type: PiiType::CreditCard,
                    patterns: vec![
                        pat(
                            r"(?i)^(credit[-_]?card|cc)[-_]?(number|num|no)?$",
                            Confidence::High,
                        ),
                        pat(r"(?i)^card[-_]?number$", Confidence::High),
                        pat(r"(?i)^pan$", Confidence::Medium),
                    ],
                    default_severity: Severity::Critical,
                    category: PiiCategory::FinancialInfo,
                },
                DictionaryEntry {
                    pii_type: PiiType::BankAccount,
                    patterns: vec![pat(
                        r"(?i)^(bank[-_]?)?account[-_]?(number|num|no)?$",
                        Confidence::High,
                    )],
                    default_severity: Severity::Critical,
                    category: PiiCategory::FinancialInfo,
                },
                DictionaryEntry {
                    pii_type: PiiType::Salary,
                    patterns: vec![pat(
                        r"(?i)^(salary|wage|income|compensation|pay[-_]?rate)$",
                        Confidence::High,
                    )],
                    default_severity: Severity::High,
                    category: PiiCategory::FinancialInfo,
                },
                // ── Auth Credentials ──
                DictionaryEntry {
                    pii_type: PiiType::Password,
                    patterns: vec![
                        pat(
                            r"(?i)^(password|passwd|pass[-_]?word|pwd|secret)$",
                            Confidence::High,
                        ),
                        pat(r"(?i)^(password|passwd)[-_]?hash$", Confidence::Medium),
                    ],
                    default_severity: Severity::Critical,
                    category: PiiCategory::AuthCredential,
                },
                DictionaryEntry {
                    pii_type: PiiType::AuthToken,
                    patterns: vec![
                        pat(r"(?i)^(auth[-_]?)?token$", Confidence::High),
                        pat(
                            r"(?i)^(access|refresh|bearer|session)[-_]?token$",
                            Confidence::High,
                        ),
                        pat(r"(?i)^(jwt|oauth)[-_]?token$", Confidence::High),
                    ],
                    default_severity: Severity::Critical,
                    category: PiiCategory::AuthCredential,
                },
                DictionaryEntry {
                    pii_type: PiiType::ApiKey,
                    patterns: vec![
                        pat(r"(?i)^api[-_]?key$", Confidence::High),
                        pat(r"(?i)^(secret|private)[-_]?key$", Confidence::High),
                        pat(
                            r"(?i)^(aws|gcp|azure)[-_]?(access[-_]?)?key$",
                            Confidence::High,
                        ),
                    ],
                    default_severity: Severity::Critical,
                    category: PiiCategory::AuthCredential,
                },
                // ── Health ──
                DictionaryEntry {
                    pii_type: PiiType::HealthData,
                    patterns: vec![
                        pat(
                            r"(?i)^(health|medical)[-_]?(data|info|record|condition|history)$",
                            Confidence::High,
                        ),
                        pat(
                            r"(?i)^(diagnosis|treatment|medication|allergy|blood[-_]?type)$",
                            Confidence::High,
                        ),
                    ],
                    default_severity: Severity::Critical,
                    category: PiiCategory::HealthInfo,
                },
                DictionaryEntry {
                    pii_type: PiiType::MedicalRecord,
                    patterns: vec![
                        pat(
                            r"(?i)^(medical|health)[-_]?record[-_]?(number|num|no|id)?$",
                            Confidence::High,
                        ),
                        pat(r"(?i)^(mrn|patient[-_]?id)$", Confidence::High),
                    ],
                    default_severity: Severity::Critical,
                    category: PiiCategory::HealthInfo,
                },
                // ── Contact: new ──
                DictionaryEntry {
                    pii_type: PiiType::PostalCode,
                    patterns: vec![
                        pat(r"(?i)^(postal|zip)[-_]?code$", Confidence::High),
                        pat(r"(?i)^(postcode|zip)$", Confidence::High),
                    ],
                    default_severity: Severity::Medium,
                    category: PiiCategory::ContactInfo,
                },
                DictionaryEntry {
                    pii_type: PiiType::Fax,
                    patterns: vec![pat(r"(?i)^fax[-_]?(number|num|no)?$", Confidence::High)],
                    default_severity: Severity::Medium,
                    category: PiiCategory::ContactInfo,
                },
                // ── Personal: new ──
                DictionaryEntry {
                    pii_type: PiiType::FirstName,
                    patterns: vec![
                        pat(r"(?i)^first[-_]?name$", Confidence::High),
                        pat(r"(?i)^given[-_]?name$", Confidence::High),
                        pat(r"(?i)^fname$", Confidence::Medium),
                    ],
                    default_severity: Severity::High,
                    category: PiiCategory::PersonalAttribute,
                },
                DictionaryEntry {
                    pii_type: PiiType::LastName,
                    patterns: vec![
                        pat(r"(?i)^last[-_]?name$", Confidence::High),
                        pat(r"(?i)^(family|sur)[-_]?name$", Confidence::High),
                        pat(r"(?i)^lname$", Confidence::Medium),
                    ],
                    default_severity: Severity::High,
                    category: PiiCategory::PersonalAttribute,
                },
                DictionaryEntry {
                    pii_type: PiiType::Nationality,
                    patterns: vec![
                        pat(r"(?i)^nationality$", Confidence::High),
                        pat(r"(?i)^citizenship$", Confidence::High),
                    ],
                    default_severity: Severity::Medium,
                    category: PiiCategory::PersonalAttribute,
                },
                DictionaryEntry {
                    pii_type: PiiType::Ethnicity,
                    patterns: vec![pat(
                        r"(?i)^(ethnicity|race|ethnic[-_]?group)$",
                        Confidence::High,
                    )],
                    default_severity: Severity::High,
                    category: PiiCategory::PersonalAttribute,
                },
                // ── Government IDs: new ──
                DictionaryEntry {
                    pii_type: PiiType::DriversLicense,
                    patterns: vec![
                        pat(
                            r"(?i)^driver('?s)?[-_]?licen[sc]e[-_]?(number|num|no|id)?$",
                            Confidence::High,
                        ),
                        pat(
                            r"(?i)^(dl|driving)[-_]?(license|licence)$",
                            Confidence::High,
                        ),
                    ],
                    default_severity: Severity::Critical,
                    category: PiiCategory::GovernmentId,
                },
                DictionaryEntry {
                    pii_type: PiiType::TaxId,
                    patterns: vec![
                        pat(
                            r"(?i)^tax[-_]?(id|number|num|no|identification)$",
                            Confidence::High,
                        ),
                        pat(r"(?i)^(tin|vat[-_]?number|ein|itin)$", Confidence::High),
                    ],
                    default_severity: Severity::Critical,
                    category: PiiCategory::GovernmentId,
                },
                DictionaryEntry {
                    pii_type: PiiType::VoterId,
                    patterns: vec![pat(r"(?i)^voter[-_]?(id|card|number)$", Confidence::High)],
                    default_severity: Severity::Critical,
                    category: PiiCategory::GovernmentId,
                },
                // ── Regional: Japan ──
                DictionaryEntry {
                    pii_type: PiiType::MyNumber,
                    patterns: vec![
                        pat(r"(?i)^my[-_]?number$", Confidence::High),
                        pat(
                            r"(?i)^(kojin[-_]?bango|individual[-_]?number)$",
                            Confidence::High,
                        ),
                        pat(
                            r"(?i)^(juminhyo|juki)[-_]?(code|number|no)?$",
                            Confidence::Medium,
                        ),
                    ],
                    default_severity: Severity::Critical,
                    category: PiiCategory::GovernmentId,
                },
                // ── Regional: EU ──
                DictionaryEntry {
                    pii_type: PiiType::Iban,
                    patterns: vec![
                        pat(r"(?i)^iban$", Confidence::High),
                        pat(r"(?i)^iban[-_]?(number|no|code)$", Confidence::High),
                    ],
                    default_severity: Severity::Critical,
                    category: PiiCategory::FinancialInfo,
                },
                // ── Regional: Netherlands ──
                DictionaryEntry {
                    pii_type: PiiType::Bsn,
                    patterns: vec![
                        pat(r"(?i)^bsn$", Confidence::High),
                        pat(r"(?i)^burger[-_]?service[-_]?nummer$", Confidence::High),
                    ],
                    default_severity: Severity::Critical,
                    category: PiiCategory::GovernmentId,
                },
                // ── Regional: UK ──
                DictionaryEntry {
                    pii_type: PiiType::Nhs,
                    patterns: vec![
                        pat(r"(?i)^nhs[-_]?(number|num|no|id)?$", Confidence::High),
                        pat(r"(?i)^ni[-_]?(number|no)$", Confidence::High),
                    ],
                    default_severity: Severity::Critical,
                    category: PiiCategory::GovernmentId,
                },
                // ── Financial: new ──
                DictionaryEntry {
                    pii_type: PiiType::BankRoutingNumber,
                    patterns: vec![
                        pat(r"(?i)^routing[-_]?(number|num|no)$", Confidence::High),
                        pat(r"(?i)^(aba|sort)[-_]?(code|number)$", Confidence::High),
                    ],
                    default_severity: Severity::Critical,
                    category: PiiCategory::FinancialInfo,
                },
                DictionaryEntry {
                    pii_type: PiiType::SwiftCode,
                    patterns: vec![pat(
                        r"(?i)^(swift|bic)[-_]?(code|number)?$",
                        Confidence::High,
                    )],
                    default_severity: Severity::High,
                    category: PiiCategory::FinancialInfo,
                },
                DictionaryEntry {
                    pii_type: PiiType::CryptoWallet,
                    patterns: vec![pat(
                        r"(?i)^(crypto|bitcoin|btc|eth|wallet)[-_]?(addr(ess)?|id)$",
                        Confidence::High,
                    )],
                    default_severity: Severity::High,
                    category: PiiCategory::FinancialInfo,
                },
                DictionaryEntry {
                    pii_type: PiiType::InsuranceId,
                    patterns: vec![
                        pat(
                            r"(?i)^insurance[-_]?(id|number|num|no|policy)$",
                            Confidence::High,
                        ),
                        pat(r"(?i)^policy[-_]?(number|num|no|id)$", Confidence::High),
                    ],
                    default_severity: Severity::High,
                    category: PiiCategory::FinancialInfo,
                },
                // ── Auth: new ──
                DictionaryEntry {
                    pii_type: PiiType::PrivateKey,
                    patterns: vec![
                        pat(r"(?i)^private[-_]?key$", Confidence::High),
                        pat(
                            r"(?i)^(rsa|ssh|pgp|gpg)[-_]?(private[-_]?)?key$",
                            Confidence::High,
                        ),
                    ],
                    default_severity: Severity::Critical,
                    category: PiiCategory::AuthCredential,
                },
                DictionaryEntry {
                    pii_type: PiiType::SecretKey,
                    patterns: vec![
                        pat(r"(?i)^secret[-_]?key$", Confidence::High),
                        pat(r"(?i)^(encryption|signing|hmac)[-_]?key$", Confidence::High),
                        pat(r"(?i)^client[-_]?secret$", Confidence::High),
                    ],
                    default_severity: Severity::Critical,
                    category: PiiCategory::AuthCredential,
                },
                // ── Health: new ──
                DictionaryEntry {
                    pii_type: PiiType::Diagnosis,
                    patterns: vec![
                        pat(r"(?i)^diagnosis$", Confidence::High),
                        pat(r"(?i)^(medical[-_]?)?condition$", Confidence::Medium),
                    ],
                    default_severity: Severity::Critical,
                    category: PiiCategory::HealthInfo,
                },
                DictionaryEntry {
                    pii_type: PiiType::Prescription,
                    patterns: vec![pat(
                        r"(?i)^(prescription|medication|drug[-_]?name)$",
                        Confidence::High,
                    )],
                    default_severity: Severity::Critical,
                    category: PiiCategory::HealthInfo,
                },
                // ── Biometric ──
                DictionaryEntry {
                    pii_type: PiiType::Biometric,
                    patterns: vec![pat(
                        r"(?i)^biometric[-_]?(data|id|hash|template)?$",
                        Confidence::High,
                    )],
                    default_severity: Severity::Critical,
                    category: PiiCategory::BiometricData,
                },
                DictionaryEntry {
                    pii_type: PiiType::FaceImage,
                    patterns: vec![
                        pat(
                            r"(?i)^face[-_]?(image|photo|data|encoding|embedding)$",
                            Confidence::High,
                        ),
                        pat(
                            r"(?i)^(profile[-_]?photo|avatar[-_]?image|selfie)$",
                            Confidence::Medium,
                        ),
                    ],
                    default_severity: Severity::Critical,
                    category: PiiCategory::BiometricData,
                },
                DictionaryEntry {
                    pii_type: PiiType::Fingerprint,
                    patterns: vec![pat(
                        r"(?i)^fingerprint[-_]?(data|hash|template|id)?$",
                        Confidence::High,
                    )],
                    default_severity: Severity::Critical,
                    category: PiiCategory::BiometricData,
                },
                // ── Browser/Device ──
                DictionaryEntry {
                    pii_type: PiiType::UserAgent,
                    patterns: vec![pat(r"(?i)^user[-_]?agent$", Confidence::High)],
                    default_severity: Severity::Low,
                    category: PiiCategory::BrowserDevice,
                },
                DictionaryEntry {
                    pii_type: PiiType::DeviceId,
                    patterns: vec![
                        pat(
                            r"(?i)^device[-_]?(id|identifier|fingerprint)$",
                            Confidence::High,
                        ),
                        pat(r"(?i)^(udid|imei)$", Confidence::High),
                    ],
                    default_severity: Severity::Medium,
                    category: PiiCategory::BrowserDevice,
                },
                DictionaryEntry {
                    pii_type: PiiType::Cookie,
                    patterns: vec![
                        pat(
                            r"(?i)^(cookie|session[-_]?cookie|tracking[-_]?cookie)$",
                            Confidence::High,
                        ),
                        pat(r"(?i)^set[-_]?cookie$", Confidence::Medium),
                    ],
                    default_severity: Severity::Medium,
                    category: PiiCategory::BrowserDevice,
                },
                DictionaryEntry {
                    pii_type: PiiType::MacAddress,
                    patterns: vec![pat(r"(?i)^mac[-_]?addr(ess)?$", Confidence::High)],
                    default_severity: Severity::Medium,
                    category: PiiCategory::NetworkIdentifier,
                },
                DictionaryEntry {
                    pii_type: PiiType::SessionId,
                    patterns: vec![
                        pat(r"(?i)^session[-_]?(id|key|token)$", Confidence::High),
                        pat(r"(?i)^sid$", Confidence::Medium),
                    ],
                    default_severity: Severity::Medium,
                    category: PiiCategory::BrowserDevice,
                },
                DictionaryEntry {
                    pii_type: PiiType::GpsCoordinates,
                    patterns: vec![
                        pat(
                            r"(?i)^(gps|geo)[-_]?(loc(ation)?|coord(inates)?|lat(itude)?|lng|lon(gitude)?)$",
                            Confidence::High,
                        ),
                        pat(r"(?i)^(latitude|longitude)$", Confidence::High),
                    ],
                    default_severity: Severity::Medium,
                    category: PiiCategory::NetworkIdentifier,
                },
                // ── Education / Employment ──
                DictionaryEntry {
                    pii_type: PiiType::StudentId,
                    patterns: vec![pat(
                        r"(?i)^student[-_]?(id|number|num|no)$",
                        Confidence::High,
                    )],
                    default_severity: Severity::High,
                    category: PiiCategory::EducationEmployment,
                },
                DictionaryEntry {
                    pii_type: PiiType::EmployeeId,
                    patterns: vec![
                        pat(r"(?i)^employee[-_]?(id|number|num|no)$", Confidence::High),
                        pat(
                            r"(?i)^(staff|worker|personnel)[-_]?(id|number)$",
                            Confidence::High,
                        ),
                    ],
                    default_severity: Severity::High,
                    category: PiiCategory::EducationEmployment,
                },
                DictionaryEntry {
                    pii_type: PiiType::SocialMediaHandle,
                    patterns: vec![
                        pat(
                            r"(?i)^(twitter|instagram|facebook|linkedin|tiktok|github)[-_]?(handle|username|id|profile)$",
                            Confidence::High,
                        ),
                        pat(
                            r"(?i)^social[-_]?media[-_]?(handle|username|id)$",
                            Confidence::High,
                        ),
                    ],
                    default_severity: Severity::Medium,
                    category: PiiCategory::EducationEmployment,
                },
            ],
        }
    }

    /// Load custom PII types from config and merge into this dictionary.
    pub fn load_custom(&mut self, custom_types: &[crate::config::CustomPiiType]) {
        for ct in custom_types {
            let mut patterns = Vec::new();
            for p in &ct.patterns {
                match Regex::new(p) {
                    Ok(re) => patterns.push(IdentifierPattern {
                        regex: re,
                        confidence: Confidence::High,
                    }),
                    Err(e) => {
                        eprintln!(
                            "Warning: invalid regex '{}' for custom PII type '{}': {}",
                            p, ct.name, e
                        );
                    }
                }
            }
            if !patterns.is_empty() {
                let severity = ct
                    .severity
                    .as_deref()
                    .and_then(|s| s.parse::<Severity>().ok())
                    .unwrap_or(Severity::High);

                self.entries.push(DictionaryEntry {
                    pii_type: PiiType::Custom(ct.name.clone()),
                    patterns,
                    default_severity: severity,
                    category: PiiCategory::Custom,
                });
            }
        }
    }

    pub fn match_identifier(&self, name: &str) -> Option<PiiMatch> {
        let mut best_match: Option<PiiMatch> = None;

        for entry in &self.entries {
            for pattern in &entry.patterns {
                if pattern.regex.is_match(name) {
                    let candidate = PiiMatch {
                        pii_type: entry.pii_type.clone(),
                        category: entry.category,
                        severity: entry.default_severity,
                        confidence: pattern.confidence,
                    };
                    // Keep highest confidence match
                    match &best_match {
                        None => best_match = Some(candidate),
                        Some(existing)
                            if (candidate.confidence as u8) > (existing.confidence as u8) =>
                        {
                            best_match = Some(candidate);
                        }
                        _ => {}
                    }
                }
            }
        }

        best_match
    }
}

#[derive(Debug, Clone)]
pub struct PiiMatch {
    pub pii_type: PiiType,
    pub category: PiiCategory,
    pub severity: Severity,
    pub confidence: Confidence,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dict() -> PiiDictionary {
        PiiDictionary::builtin()
    }

    #[test]
    fn match_email_variants() {
        let d = dict();
        assert_eq!(
            d.match_identifier("email").unwrap().pii_type,
            PiiType::Email
        );
        assert_eq!(
            d.match_identifier("user_email").unwrap().pii_type,
            PiiType::Email
        );
        assert_eq!(
            d.match_identifier("emailAddress").unwrap().pii_type,
            PiiType::Email
        );
        assert_eq!(
            d.match_identifier("EMAIL").unwrap().pii_type,
            PiiType::Email
        );
    }

    #[test]
    fn match_password() {
        let d = dict();
        assert_eq!(
            d.match_identifier("password").unwrap().pii_type,
            PiiType::Password
        );
        assert_eq!(
            d.match_identifier("passwd").unwrap().pii_type,
            PiiType::Password
        );
        assert_eq!(
            d.match_identifier("PASSWORD").unwrap().pii_type,
            PiiType::Password
        );
    }

    #[test]
    fn match_ip_address() {
        let d = dict();
        assert_eq!(
            d.match_identifier("ip_address").unwrap().pii_type,
            PiiType::IpAddress
        );
        assert_eq!(
            d.match_identifier("clientIp").unwrap().pii_type,
            PiiType::IpAddress
        );
        assert_eq!(
            d.match_identifier("remote_ip").unwrap().pii_type,
            PiiType::IpAddress
        );
    }

    #[test]
    fn no_match_for_safe_names() {
        let d = dict();
        assert!(d.match_identifier("count").is_none());
        assert!(d.match_identifier("total").is_none());
        assert!(d.match_identifier("isActive").is_none());
        assert!(d.match_identifier("created_at").is_none());
    }

    #[test]
    fn match_national_id() {
        let d = dict();
        assert_eq!(
            d.match_identifier("ssn").unwrap().pii_type,
            PiiType::NationalId
        );
        assert_eq!(
            d.match_identifier("social_security_number")
                .unwrap()
                .pii_type,
            PiiType::NationalId
        );
        assert_eq!(
            d.match_identifier("national_id").unwrap().pii_type,
            PiiType::NationalId
        );
    }

    #[test]
    fn match_credit_card() {
        let d = dict();
        assert_eq!(
            d.match_identifier("credit_card").unwrap().pii_type,
            PiiType::CreditCard
        );
        assert_eq!(
            d.match_identifier("card_number").unwrap().pii_type,
            PiiType::CreditCard
        );
        assert_eq!(
            d.match_identifier("cc_number").unwrap().pii_type,
            PiiType::CreditCard
        );
    }

    #[test]
    fn confidence_high_wins() {
        let d = dict();
        let m = d.match_identifier("email").unwrap();
        assert_eq!(m.confidence, Confidence::High);
    }

    // ── New PII type tests ──

    #[test]
    fn match_regional_japan_my_number() {
        let d = dict();
        assert_eq!(
            d.match_identifier("my_number").unwrap().pii_type,
            PiiType::MyNumber
        );
        assert_eq!(
            d.match_identifier("kojin_bango").unwrap().pii_type,
            PiiType::MyNumber
        );
    }

    #[test]
    fn match_regional_eu_iban() {
        let d = dict();
        assert_eq!(d.match_identifier("iban").unwrap().pii_type, PiiType::Iban);
        assert_eq!(d.match_identifier("IBAN").unwrap().pii_type, PiiType::Iban);
    }

    #[test]
    fn match_regional_nl_bsn() {
        let d = dict();
        assert_eq!(d.match_identifier("bsn").unwrap().pii_type, PiiType::Bsn);
    }

    #[test]
    fn match_regional_uk_nhs() {
        let d = dict();
        assert_eq!(
            d.match_identifier("nhs_number").unwrap().pii_type,
            PiiType::Nhs
        );
    }

    #[test]
    fn match_drivers_license() {
        let d = dict();
        assert_eq!(
            d.match_identifier("drivers_license").unwrap().pii_type,
            PiiType::DriversLicense
        );
        assert_eq!(
            d.match_identifier("driving_license").unwrap().pii_type,
            PiiType::DriversLicense
        );
    }

    #[test]
    fn match_biometric() {
        let d = dict();
        assert_eq!(
            d.match_identifier("biometric_data").unwrap().pii_type,
            PiiType::Biometric
        );
        assert_eq!(
            d.match_identifier("fingerprint").unwrap().pii_type,
            PiiType::Fingerprint
        );
        assert_eq!(
            d.match_identifier("face_image").unwrap().pii_type,
            PiiType::FaceImage
        );
    }

    #[test]
    fn match_gps_coordinates() {
        let d = dict();
        assert_eq!(
            d.match_identifier("gps_location").unwrap().pii_type,
            PiiType::GpsCoordinates
        );
        assert_eq!(
            d.match_identifier("latitude").unwrap().pii_type,
            PiiType::GpsCoordinates
        );
        assert_eq!(
            d.match_identifier("longitude").unwrap().pii_type,
            PiiType::GpsCoordinates
        );
    }

    #[test]
    fn match_crypto_wallet() {
        let d = dict();
        assert_eq!(
            d.match_identifier("bitcoin_address").unwrap().pii_type,
            PiiType::CryptoWallet
        );
        assert_eq!(
            d.match_identifier("wallet_addr").unwrap().pii_type,
            PiiType::CryptoWallet
        );
    }

    #[test]
    fn match_employee_student() {
        let d = dict();
        assert_eq!(
            d.match_identifier("employee_id").unwrap().pii_type,
            PiiType::EmployeeId
        );
        assert_eq!(
            d.match_identifier("student_number").unwrap().pii_type,
            PiiType::StudentId
        );
    }

    #[test]
    fn match_social_media() {
        let d = dict();
        assert_eq!(
            d.match_identifier("twitter_handle").unwrap().pii_type,
            PiiType::SocialMediaHandle
        );
        assert_eq!(
            d.match_identifier("github_username").unwrap().pii_type,
            PiiType::SocialMediaHandle
        );
    }

    #[test]
    fn custom_pii_type_loading() {
        let mut d = dict();
        d.load_custom(&[crate::config::CustomPiiType {
            name: "loyalty_card".to_string(),
            patterns: vec![r"(?i)^loyalty[-_]?(card|id|number)$".to_string()],
            severity: Some("high".to_string()),
        }]);
        let m = d.match_identifier("loyalty_card").unwrap();
        assert_eq!(m.pii_type, PiiType::Custom("loyalty_card".to_string()));
        assert_eq!(m.severity, Severity::High);
    }

    #[test]
    fn custom_pii_invalid_regex_skipped() {
        let mut d = dict();
        let before = d.entries.len();
        d.load_custom(&[crate::config::CustomPiiType {
            name: "bad_type".to_string(),
            patterns: vec!["[invalid".to_string()],
            severity: None,
        }]);
        // Invalid regex should not add an entry
        assert_eq!(d.entries.len(), before);
    }

    #[test]
    fn builtin_dictionary_has_50_types() {
        let d = dict();
        let type_count = d.entries.len();
        assert!(type_count >= 50, "expected >= 50 types, got {}", type_count);
    }
}
